# fixed-malscan

Fast, **read-only** scanner for WordPress (and other PHP) sites. It finds obfuscated
JS/PHP injections (disguised script loaders, webshells, `$GLOBALS` hex tricks,
char-by-char code, `chr()` lists), webshell techniques (disable_functions /
open_basedir bypasses, reading system files), cloaking and redirects (different
content for Google, bots, mobile or first-time visitors; `.htaccess` and template
redirects), fake images (PHP/HTML saved as `.jpg`/`.png`), unknown PHP files in the
WordPress root and exposed files (wp-config / PHP backups, PHP in uploads), decodes
hidden URLs, and shows the flagged code.

> Findings are **indicators for review, not confirmed infections.**
> Always verify before reporting to a client.

## Run

From inside the site folder (`public_html`, `httpdocs`, `www`, …):

```bash
curl --proto '=https' -fsSL https://raw.githubusercontent.com/Fixed-net/fixed-malscan/main/fixed-malscan.sh | bash
```

With options, or for another folder:

```bash
# all files + full code context
curl --proto '=https' -fsSL https://raw.githubusercontent.com/Fixed-net/fixed-malscan/main/fixed-malscan.sh | bash -s -- -v
# also look for these domains
curl --proto '=https' -fsSL https://raw.githubusercontent.com/Fixed-net/fixed-malscan/main/fixed-malscan.sh | bash -s -- --watch dom1.com,dom2.net
# another folder + cross-check
curl --proto '=https' -fsSL https://raw.githubusercontent.com/Fixed-net/fixed-malscan/main/fixed-malscan.sh | bash -s -- /path/to/site --verify
```

No curl? Use `wget -qO- https://raw.githubusercontent.com/Fixed-net/fixed-malscan/main/fixed-malscan.sh | bash`.

A specific release instead of the latest: replace `main` with the tag, e.g. `.../fixed-malscan/v2.7/fixed-malscan.sh`.

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
- `reason` lines say why a check fired (e.g. *visitors by referrer (google) get: redirect
  -> example.com*); the target domain is also listed under Hidden domains.
- `new` = file modified in the last 7 days.

### Known limits

- Fake images: only the first 256 KB and the last 64 KB of each image are read (speed);
  PHP hidden in the middle of a large image's pixel data is not seen.
- Cloaking: the redirect/output must follow the visitor test within 12 lines (40 for
  "came from a search engine"); one moved into another function is not linked.
- Plain redirects in plugin PHP/JS are not checked (plugins legitimately link to their own
  services); only `.htaccess`, inline template `<script>`/meta refresh and first-visit
  (cookie) redirects are.
- Only files are scanned: injections stored in the database (`wp_options`, posts) are not.

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
- `register_patterns` – a list of `LITERAL REGEX` pairs (e.g. the webshell technique list)
- `rate_<ID>` – optional: rate each match by its content (other severity, `skip` = ignored,
  `ok` = clean); gets every match of the check at once, with file and line
- `allow` – hide a known false positive for specific checks (last resort: prefer `rate_<ID>`)

A broken regex stops the run; `--verify` shows `DIFF` if a new check would miss matches.
`bash tests/run.sh` scans the synthetic samples in `tests/samples` (malicious ones must be flagged,
known false positives must stay quiet) and compares every result with `tests/expected.txt`.
Add a sample for each new check or false-positive fix (`tests/make-samples.pl`).
Bump `VERSION` in the script and create a matching release tag (e.g. `v2.8`) for each change.
