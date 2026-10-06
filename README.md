# fixed-malscan

Fast, **read-only** scanner for WordPress (and other PHP) sites. It finds obfuscated
JS/PHP injections (disguised script loaders, webshells, `$GLOBALS` hex tricks,
char-by-char code) and exposed files (wp-config / PHP backups, PHP in uploads),
decodes hidden URLs, and shows the flagged code.

> Findings are **indicators for review, not confirmed infections.**
> Always verify before reporting to a client.

## Run

From inside the site folder (`public_html`, `httpdocs`, `www`, …):

```bash
curl --proto '=https' -fsSL https://raw.githubusercontent.com/<org>/fixed-malscan/main/fixed-malscan.sh | bash
```

With options, or for another folder:

```bash
curl --proto '=https' -fsSL <raw URL> | bash -s -- -v                       # all files + full code context
curl --proto '=https' -fsSL <raw URL> | bash -s -- --watch dom1.com,dom2.net # also look for these domains
curl --proto '=https' -fsSL <raw URL> | bash -s -- /path/to/site --verify    # another folder + cross-check
```

No curl? Use `wget -qO- <raw URL> | bash`.

## Options

| Option | What it does |
|---|---|
| `-v` | List every file, every match with code context, and ignored files with the reason |
| `-w, --watch D1,D2` | Also look for these domains in plain text. Nothing is built in; matches appear in a separate **Watchlist** section as leads to confirm |
| `--watch-file F` | Same, from a file on the server (one domain per line, `#` comments) |
| `--verify` | Re-run every check the slow, brute-force way and compare (proves nothing was skipped) |
| `-c ID,ID` | Run only some checks (see `-l`) |
| `-l` | List checks, allowlist rules and the watchlist |
| `-o FILE` | Also save a plain-text report (must be outside the scanned folder) |
| `--include-core` | Also scan `wp-admin` / `wp-includes` (skipped by default: use `wp core verify-checksums`) |
| `--no-allowlist` | Don't hide known false positives |
| `--no-color` | Plain output |

Exit codes: `0` clean · `1` findings · `2` error (stops with a `[x]` message).

## Reading the results

- Sections are ordered by severity; malicious code comes before exposed files.
- Each file is listed once, as `path:row`, with the flagged **code** (matched part in bold)
  and any **decoded** value. `also` lines show another part of the same injection.
- **Hidden domains** were decoded from obfuscated code. Legit code rarely disguises URLs,
  so treat them as suspicious until checked on VirusTotal and GTMetrix (several test locations).
- `new` = file modified in the last 7 days.

## Safety

- Site files are only ever read; nothing found is executed; symlinks are not followed.
- The only writes are a private temp dir (removed on exit), an optional `-o` report outside the
  scanned folder, and the script deleting itself if it was run from a saved file.
- Runs at the lowest CPU/IO priority; files over 20 MB are skipped and reported.
- Requires bash ≥ 4.2, perl and GNU grep/find (standard on Linux hosting). Missing tools stop the
  run with a clear error instead of giving a false "clean".

## Adding checks

Everything is in the `CHECK REGISTRY` section of the script; each check is one line:

- `register_check` – a code pattern (regex), optional decoder
- `register_file_check` – a file name/path rule, optional `classify_<ID>` for per-file severity
- `register_signatures` – a list of plain words (no regex needed)
- `rate_<ID>` – optional: rate each match by its content (other severity, or `skip`)
- `allow` – hide a known false positive for specific checks (last resort: prefer `rate_<ID>`)

A broken regex stops the run; `--verify` shows `DIFF` if a new check would miss matches.
`bash tests/run.sh` scans the synthetic samples in `tests/samples` (malicious ones must be flagged,
known false positives must stay quiet) and compares every result with `tests/expected.txt`.
Add a sample for each new check or false-positive fix (`tests/make-samples.pl`).
Bump `VERSION` in the script and create a matching release tag (e.g. `v2.6`) for each change.
