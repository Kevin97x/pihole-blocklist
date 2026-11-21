# Personal Pi-hole blocklists

Two profiles, one output domain per line. Duplicate domains are removed, input formats are normalized, and an allowlist is applied. The build reports count overlaps between source lists.

## Recommended profile

`balanced` = HaGeZi Pro + HaGeZi TIF, using their plain domain files from the legacy-format repository. Most homes should use **only this profile**, rather than installing all legacy source lists too.

`full` = experimental collection assembled from the source URLs supplied by the user and visible in their screenshots. Its sources can be dead, very broad, redundant, inappropriate for household devices or overblocking. Adult/social-media lists are included **only in full**.

## How to activate

1. Create a **public** GitHub repository and upload the contents of this folder (including `.github/workflows/update.yml`).
2. Open GitHub **Actions → Update Pi-hole blocklists → Run workflow** with `balanced` selected. GitHub will create `blocklist-balanced.txt` and `report-balanced.json` in the root of the repository.
3. Add this Pi-hole adlist URL:

   `https://raw.githubusercontent.com/YOUR-USERNAME/YOUR-REPO/main/blocklist-balanced.txt`

   Or import the same URL into Technitium DNS as a domain blocking list.
4. Run Gravity update in Pi-hole. Disable your previously enabled source lists **only after** verifying the new list has been fetched and parsed successfully.
5. The balanced profile updates automatically once a day (GitHub schedule may be delayed). Manual workflow with `full` produces a **separate** `blocklist-full.txt` and `report-full.json`.

## Customize

- `sources-balanced.txt` / `sources-full.txt`: HTTPS sources, one per line.
- `allowlist.txt`: domains that must never be included in your generated blocklist.
- `denylist.txt`: personal domains to add to both profiles.
- `report-*.json`: source statuses and count of duplicate domains removed.

## Run locally

Requires Python 3.10+; no dependencies:

```bash
python build.py --profile balanced
python build.py --profile full
```

## Safeguards and limits

- No output is overwritten if **any** source fails or fewer than 10,000 domains survive. This protects existing output but also means the full profile could require maintenance as sources disappear. Do not blindly enable `--allow-partial`.
- Only domain-only, conventional hosts records (sinkhole addresses 0.0.0.0/127.0.0.1/::/::1), and simple `||domain^` DNS block rules are imported. Cosmetic/regex/exception rules and other adblock syntax are ignored. Unsupported rules are **not** automatically converted.
- An allowlist entry removes the **exact domain** from output; it does not remove subdomains automatically.
- Sorting/normalization happens case-insensitively and includes IDNA internationalized domains; DNS blocklist domains only, not IP-based blocking.
- All lists in full are experimental. Inspect publishers' license/redistribution terms before publishing a merged copy publicly. Use only lists you are permitted to redistribute and retain attribution as required.
- Avoid deploying both outputs concurrently. Benchmark failure rates and DNS false positives before migrating all devices.
