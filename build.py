#!/usr/bin/env python3
"""Merge hosts/domain/DNS-style adblock sources into a Pi-hole-ready domain list."""
import argparse
import concurrent.futures
import ipaddress
import json
import re
import sys
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)
HOST_ADDR = {"0.0.0.0", "127.0.0.1", "::", "::1"}
MAX_BYTES = 100 * 1024 * 1024


def normalized(value):
    value = value.strip().lower().rstrip('.')
    if not value or '*' in value or '/' in value or ':' in value:
        return None
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError:
        return None
    if value in {'localhost', 'localhost.localdomain', 'local', 'broadcasthost'}:
        return None
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass
    return value if DOMAIN.fullmatch(value) else None


def parse_line(line):
    line = line.strip().lstrip('\ufeff')
    if not line or line.startswith(('#', '!', '[', '/', '@@', '$')):
        return []
    # DNS-level Adblock syntax only, not cosmetic, regex, or exception rules.
    if line.startswith('||'):
        m = re.fullmatch(r'\|\|([^\^/$|]+)\^', line)
        return [m.group(1)] if m else []
    line = line.split('#', 1)[0].strip()
    tokens = line.split()
    if not tokens:
        return []
    if tokens[0] in HOST_ADDR:
        return tokens[1:]
    # Other IP address hosts entries are deliberately ignored.
    try:
        ipaddress.ip_address(tokens[0])
        return []
    except ValueError:
        pass
    return [tokens[0]] if len(tokens) == 1 else []


def local_domains(path):
    domains = set()
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        for raw in parse_line(line):
            domain = normalized(raw)
            if domain:
                domains.add(domain)
    return domains


def source_urls(path):
    lines = Path(path).read_text(encoding='utf-8').splitlines()
    urls = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith('#')]
    if any(not line.startswith('https://') for line in urls):
        raise ValueError('Only HTTPS source URLs are accepted')
    return list(dict.fromkeys(urls))


def download(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'PiHolePersonalBlocklist/1.0', 'Accept': 'text/plain'})
    with urllib.request.urlopen(req, timeout=45) as response:
        data = response.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError('Source exceeded 100 MiB size limit')
        content_type = response.headers.get('Content-Type', '')
    body = data.decode('utf-8-sig', errors='replace')
    if ('text/html' in content_type.lower() or body.lstrip().lower().startswith(('<!doctype html', '<html'))):
        raise ValueError('Got HTML instead of a domain list')
    domains = set()
    for line in body.splitlines():
        for raw in parse_line(line):
            domain = normalized(raw)
            if domain:
                domains.add(domain)
    if not domains:
        raise ValueError('No supported domains parsed')
    return domains


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--profile', choices=['balanced', 'full'], default='balanced')
    p.add_argument('--min-domains', type=int, default=10000)
    p.add_argument('--allow-partial', action='store_true', help='Unsafe: publish despite failed sources')
    args = p.parse_args()
    urls = source_urls(f'sources-{args.profile}.txt')
    all_domains = set()
    appearances = Counter()
    source_report = []
    failed = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        future_map = {pool.submit(download, url): url for url in urls}
        for future in concurrent.futures.as_completed(future_map):
            url = future_map[future]
            try:
                domains = future.result()
                appearances.update(domains)
                all_domains.update(domains)
                source_report.append({'url': url, 'status': 'ok', 'unique_domains_in_source': len(domains)})
                print(f'OK {len(domains):>9,}  {url}')
            except Exception as exc:
                failed.append(url)
                source_report.append({'url': url, 'status': 'failed', 'error': str(exc)})
                print(f'FAIL {url}: {exc}', file=sys.stderr)
    if failed and not args.allow_partial:
        sys.exit(f'{len(failed)} source(s) failed; NOT publishing partial list.')
    allowed = local_domains('allowlist.txt')
    denied = local_domains('denylist.txt')
    # Allowlist wins even over user-defined denylist.
    output = sorted((all_domains | denied) - allowed)
    if len(output) < args.min_domains:
        sys.exit(f'Only {len(output)} domains (< {args.min_domains}); NOT overwriting output.')
    path = Path(f'blocklist-{args.profile}.txt')
    # Deterministic output means git only updates if the domains have changed.
    path.write_text('\n'.join(output) + '\n', encoding='utf-8')
    report = {
        'profile': args.profile,
        'generated_utc': datetime.now(timezone.utc).isoformat(),
        'sources_requested': len(urls),
        'sources_failed': len(failed),
        'source_domain_occurrences': sum(appearances.values()),
        'unique_source_domains': len(all_domains),
        'duplicates_across_sources': sum(appearances.values()) - len(all_domains),
        'allowlist_entries': len(allowed),
        'denylist_entries': len(denied),
        'final_domains': len(output),
        'sources': sorted(source_report, key=lambda x: x['url']),
    }
    Path(f'report-{args.profile}.json').write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(f'Wrote {path}: {len(output):,} unique domains')


if __name__ == '__main__':
    main()
