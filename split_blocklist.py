#!/usr/bin/env python3
"""Split an already built plain-text domain blocklist for GitHub's file limit.

The builder must complete successfully before this runs. Never publish an
incomplete list: this script validates and writes all shards before deleting
its source file. Each shard contains complete domain lines.
"""
import argparse
from pathlib import Path

MIB = 1024 * 1024


def split_file(profile: str, max_mib: int) -> None:
    if profile != 'full':
        print('Balanced remains a single blocklist file; no splitting needed.')
        return

    source = Path('blocklist-full.txt')
    if not source.is_file():
        raise SystemExit(f'Missing generated file: {source}')
    limit = max_mib * MIB
    if not 0 < max_mib <= 90:
        raise SystemExit('max-mib must be between 1 and 90')

    # Write to temporary files; rename to final names only after a complete pass.
    tmp_paths = []
    files = []
    total_lines = 0
    try:
        with source.open('rb') as src:
            handle = None
            size = 0
            for line in src:
                if not line.endswith(b'\n') or not line.strip():
                    raise ValueError('Input must have nonempty newline-terminated domain lines')
                if len(line) > limit:
                    raise ValueError('One domain line exceeds the shard size limit')
                if handle is None or size + len(line) > limit:
                    if handle is not None:
                        handle.close()
                    name = Path(f'blocklist-full-part{len(tmp_paths)+1:02d}.txt')
                    temp = Path(f'{name}.tmp')
                    tmp_paths.append(temp)
                    files.append(name)
                    handle = temp.open('wb')
                    size = 0
                handle.write(line)
                size += len(line)
                total_lines += 1
            if handle is not None:
                handle.close()

        if not files:
            raise ValueError('The generated blocklist is empty')
        if sum(p.stat().st_size for p in tmp_paths) != source.stat().st_size:
            raise ValueError('Shard byte total differs from original blocklist')
        for temp, final in zip(tmp_paths, files):
            temp.replace(final)
        # Delete any stale shards left from previous, larger builds.
        valid = set(files)
        for old in Path('.').glob('blocklist-full-part*.txt'):
            if old not in valid:
                old.unlink()
        source.unlink()
        print(f'Split {total_lines:,} domains into {len(files)} files (max {max_mib} MiB):')
        for path in files:
            print(f'  {path} ({path.stat().st_size / MIB:.2f} MiB)')
    except Exception:
        for p in tmp_paths:
            p.unlink(missing_ok=True)
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', choices=['balanced', 'full'], required=True)
    parser.add_argument('--max-mib', type=int, default=40)
    arguments = parser.parse_args()
    split_file(arguments.profile, arguments.max_mib)
