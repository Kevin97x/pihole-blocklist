#!/usr/bin/env python3
"""Read-only, source-level coverage audit for the existing Pi-hole builder.

Downloads the currently configured source lists with the *same parser* as build.py.
Writes CSV and Markdown reports; does NOT modify any blocklist or source file.
"""
import concurrent.futures
import csv
import gzip
import hashlib
import os
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from build import download, source_urls

ROOT = Path('audit-results')
CORE = set(source_urls('sources-balanced.txt'))
URLS = source_urls('sources-full.txt')


def fetch_and_store(task):
    number, url, folder = task
    domains = download(url)
    dest = Path(folder) / f'{number:03d}.txt.gz'
    digest = hashlib.sha256()
    with gzip.open(dest, 'wt', encoding='utf-8', newline='\n') as fh:
        for domain in sorted(domains):
            digest.update(domain.encode('utf-8') + b'\n')
            fh.write(domain + '\n')
    return number, url, len(domains), str(dest), digest.hexdigest()


def read_domains(path):
    with gzip.open(path, 'rt', encoding='utf-8') as fh:
        for line in fh:
            yield line.rstrip('\n')


def main():
    ROOT.mkdir(exist_ok=True)
    results = {}
    failures = []
    counts = Counter()
    with tempfile.TemporaryDirectory(prefix='pihole-audit-') as temp:
        tasks = [(i, url, temp) for i, url in enumerate(URLS)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = {pool.submit(fetch_and_store, item): item for item in tasks}
            for future in concurrent.futures.as_completed(futures):
                i, url, _ = futures[future]
                try:
                    record = future.result()
                    results[i] = record
                    counts.update(read_domains(record[3]))
                    print(f'OK {record[2]:>9,} {url}', flush=True)
                except Exception as exc:
                    failures.append((url, str(exc)))
                    print(f'FAIL {url}: {exc}', flush=True)

        # Count all successful source contributions relative to the Balanced core.
        core_domains = set()
        for i, url in enumerate(URLS):
            if url in CORE and i in results:
                core_domains.update(read_domains(results[i][3]))

        rows = []
        for i, url in enumerate(URLS):
            if i not in results:
                rows.append(dict(source=url, status='FAILED', domains='', exclusive='',
                                 exclusive_pct='', covered_by_other_sources='',
                                 outside_balanced_core='', identical_content_group='', error=next(e for u,e in failures if u == url)))
                continue
            _, _, total, path, digest = results[i]
            exclusive = 0
            beyond_core = 0
            for domain in read_domains(path):
                exclusive += (counts[domain] == 1)
                beyond_core += (domain not in core_domains)
            rows.append(dict(source=url, status='OK', domains=total, exclusive=exclusive,
                             exclusive_pct=round(100 * exclusive / total, 3) if total else 0,
                             covered_by_other_sources=total - exclusive,
                             outside_balanced_core=beyond_core,
                             identical_content_group=digest, error=''))

    # Hash equality is content equality for these normalized sorted lists, modulo
    # SHA-256 collision (practically negligible). Use short IDs only for repeated groups.
    digest_freq = Counter(row['identical_content_group'] for row in rows if row['status'] == 'OK')
    for row in rows:
        digest = row['identical_content_group']
        row['identical_content_group'] = digest[:12] if digest and digest_freq[digest] > 1 else ''

    fields = ['source', 'status', 'domains', 'exclusive', 'exclusive_pct',
              'covered_by_other_sources', 'outside_balanced_core',
              'identical_content_group', 'error']
    with (ROOT / 'source-coverage.csv').open('w', encoding='utf-8', newline='') as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    valid = [r for r in rows if r['status'] == 'OK']
    valid.sort(key=lambda x: (int(x['exclusive']), int(x['domains'])))
    total_occurrences = sum(int(r['domains']) for r in valid)
    total_unique = len(counts)
    lines = [
        '# Pi-hole source coverage audit', '',
        f'Generated UTC: {datetime.now(timezone.utc).isoformat()}',
        f'Configured sources: **{len(URLS)}**; successful: **{len(valid)}**; failed: **{len(failures)}**.',
        f'Unique domains among successful sources: **{total_unique:,}**.',
        f'Source-domain occurrences: **{total_occurrences:,}**; duplicates across sources: **{total_occurrences - total_unique:,}**.',
        f'Domains in available Balanced core sources: **{len(core_domains):,}**.', '',
        '## How to interpret', '',
        '- **Exclusive:** domains only present in this one source. Removing this source *alone* loses exactly this many source domains. This is not a security-quality score.',
        '- **Outside core:** domains not in the configured Balanced core, but these may overlap other optional Full sources.',
        '- **Identical group:** same normalized, sorted domain contents (matching SHA-256). Keep at most one URL per identical group.',
        '- **Zero exclusive:** safe to remove *one at a time* without changing the current combined set. Removing several such sources together may still lose domains, so reassess after changes.',
        '- This audit cannot detect false positives or establish whether a domain is malicious.',
        '- No changes were made to source files or published blocklists.', '',
        '## Sources ranked by exclusive contribution (ascending)', '',
        '| Exclusive | Domains | % exclusive | Outside core | Identical group | Source |',
        '|---:|---:|---:|---:|---|---|',
    ]
    for r in valid:
        lines.append(f"| {r['exclusive']:,} | {r['domains']:,} | {r['exclusive_pct']:.3f}% | {r['outside_balanced_core']:,} | {r['identical_content_group'] or '—'} | `{r['source']}` |")
    if failures:
        lines.extend(['', '## Download failures', ''])
        lines.extend(f'- `{u}` — {e}' for u,e in failures)
    lines.extend(['', '## Recommended review order', '',
                  '1. Remove one duplicate from every identical-content group, rerun the audit.',
                  '2. Review tiny/zero-exclusive optional sources for maintenance, false-positive risk, and license obligations.',
                  '3. Keep phishing/threat-intelligence categories based on quality as well as exclusive count.',
                  '4. Never automatically delete every zero-exclusive source in a single batch.', ''])
    (ROOT / 'source-coverage.md').write_text('\n'.join(lines), encoding='utf-8')
    print(f'Unique: {total_unique:,}; source occurrences: {total_occurrences:,}; duplicates: {total_occurrences - total_unique:,}')
    print('Audit reports saved to audit-results/')
    if failures:
        print('NOTE: Some sources failed. Report is based only on successful downloads; do not treat it as a complete Full audit.')


if __name__ == '__main__':
    main()
