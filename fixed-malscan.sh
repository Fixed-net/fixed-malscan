#!/usr/bin/env bash
# =============================================================================
#  fixed-malscan.sh — fast scanner for obfuscated JS/PHP injections and
#  exposed PHP/config backups on WordPress (and other PHP) sites.
#
#  WP core (wp-admin, wp-includes) is skipped by default — verify it with
#  `wp core verify-checksums` instead. Use --include-core to scan it anyway.
#
#  READ-ONLY: scanned files are only ever opened for reading; nothing found is
#  executed; symlinks are not followed. The only writes are a private temp dir
#  (mktemp -d, removed on exit/Ctrl-C), an optional -o report outside the scan
#  dir, and deleting this script itself when it was run from a file (--keep).
#
#  Run without saving it, from inside the site folder (one-liner):
#      curl --proto '=https' -fsSL https://raw.githubusercontent.com/<org>/fixed-malscan/main/fixed-malscan.sh | bash
#      ... | bash -s -- [DIR] [options]        # with options / another folder
#
#  Needs: bash >= 4.2, perl, GNU grep/find/xargs/coreutils (standard on Linux
#  hosting: cPanel/CloudLinux/Plesk/DirectAdmin, Debian/Ubuntu, RHEL/Alma).
#
#  FIXED-MALSCAN-SELF-DELETE-MARKER  (only a file containing this line is deleted)
# =============================================================================

VERSION="2.7"
if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ] || \
   { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 2 ]; }; then
  echo "fixed-malscan: bash >= 4.2 required (run it with bash, not sh)" >&2; exit 2
fi
shopt -s lastpipe extglob   # pipes instead of <(...): works without /dev/fd (CageFS/jails)

# -----------------------------------------------------------------------------
#  CONFIG
# -----------------------------------------------------------------------------
DEFAULT_INCLUDES=("*.js" "*.php")
EXCLUDE_DIRS=(".git" "node_modules")
CORE_DIRS=("wp-admin" "wp-includes")   # skipped unless --include-core
CTX_BEFORE=60          # chars of code shown before a match (-v)
CTX_AFTER=100          # chars of code shown after a match (-v)
SNIPPET_MAX=180        # max snippet length (-v)
DECODE_WINDOW=600      # chars after the match handed to the decoder
LIST_LIMIT=20          # files listed per check in the summary (all with -v)
MAX_FILE_MB=20         # content checks skip larger files (reported as skipped)
RECENT_DAYS=7          # highlight files modified within this many days
export LC_ALL=C        # byte-wise matching: much faster, no locale surprises

# -----------------------------------------------------------------------------
#  CHECK REGISTRY — add new checks here
#
#  Content checks (grep the code):
#  register_check ID SEVERITY DECODER PREFILTER "Description" 'REGEX' [globs...]
#    SEVERITY  : high | medium | low
#    DECODER   : none | caesar | base64 | b64url | charcodes | hex | urlenc
#    PREFILTER : fixed string(s) a file must contain before the regex runs
#                (speed). Several = newline-separated: $'atob\nbase64_decode'.
#                MUST be a literal the regex itself requires, or matches are
#                lost (--verify will show a DIFF). Use - for none.
#    REGEX     : extended regex (used by perl and by grep -E in --verify)
#    globs     : optional --include globs (default: DEFAULT_INCLUDES)
#
#  File checks (match by name/path, one fast find pass):
#  register_file_check ID SEVERITY "Description" 'GLOB|GLOB' [exclude_globs...]
#    GLOBs     : case-insensitive, '|'-separated; matched against the file
#                NAME, or the whole PATH if the glob contains a '/'.
#    Optional classify_<ID> function sets severity per file (see below).
#
#  Summary order: HIGH before MED before LOW; within a severity, content
#  checks (malicious code) before file checks (exposed files), then in the
#  order registered below.
# -----------------------------------------------------------------------------
register_checks() {
  # ---- JS / mixed injections -----------------------------------------------
  local lits; lits=$(shifted_scheme_literals)
  register_check SHIFTED_URL high caesar "$lits" \
    "Disguised 'https://': every letter shifted by N (e.g. myyux?44 = https:// shifted +5)" \
    "$(literals_to_regex "$lits")"

  register_check CHARCODE_SHIFT high caesar 'charCodeAt' \
    "fromCharCode(x.charCodeAt() +/- N) char-shift decoder" \
    'fromCharCode(['\''"]\])?\(\s*\(?\s*[A-Za-z_$][A-Za-z0-9_$.]*\.charCodeAt\([^)]*\)\s*[-+^]\s*[0-9]{1,3}([^0-9]|$)'

  register_check FROMCHARCODE_LONG high charcodes 'fromCharCode' \
    "fromCharCode() with a long numeric list (30+ chars of hidden code)" \
    'fromCharCode\(\s*[0-9]{2,3}(\s*,\s*[0-9]{2,3}){29,}'

  register_check HEX_HTTP high hex '\x68\x74\x74\x70' \
    "Hex-escaped 'http' string" \
    '\\x68\\x74\\x74\\x70'

  register_check JS_EVAL_DECODE high none 'eval' \
    "eval() applied directly to a decoder (atob/unescape/fromCharCode)" \
    'eval\s*\(\s*(window\.)?(atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\('

  register_check JS_UNESCAPE_BLOB high urlenc 'unescape' \
    "unescape() of a %-encoded blob" \
    'unescape\s*\(\s*['\''"](%[0-9a-fA-F]{2}){8,}'

  # ---- PHP injections ------------------------------------------------------
  register_check PHP_EVAL_CHAIN high base64 $'eval\nassert' \
    "eval()/assert() wrapped directly around a decoder" \
    '(eval|assert)\s*\(\s*(gzinflate|gzuncompress|gzdecode|str_rot13|base64_decode)\s*\(' '*.php'

  register_check PHP_HEX_VARVAR high none '${' \
    "Variable-variable with hex-escaped name, e.g. \${\"\\x47\\x4c...\"} (=\$GLOBALS)" \
    '\$\{\s*["'\''][^"'\'']{0,8}\\x[0-9a-fA-F]' '*.php'

  # 4+ chained single-char lookups: $t['key'][77].$t['key'][40]... or $t[77].$t[40]...
  # (plain $hex[0].$hex[0].$hex[1] colour expansion is NOT matched)
  register_check PHP_CHAR_ASSEMBLY high none $'].\n] .' \
    "Code assembled char-by-char from a lookup table: \$t['k'][77].\$t['k'][40]..." \
    '(\$[A-Za-z_][A-Za-z0-9_]*((\[[^][]{1,40}\])+\[[0-9]{1,3}\]|\[[0-9]{2,3}\]) ?\. ?){3,}\$[A-Za-z_][A-Za-z0-9_]*((\[[^][]{1,40}\])+\[[0-9]{1,3}\]|\[[0-9]{2,3}\])' '*.php'

  register_check PHP_INPUT_EXEC high none '$_' \
    "Request data passed straight to eval/system/exec or called as a function" \
    '((^|[^A-Za-z0-9_$>:])(eval|assert|system|exec|passthru|shell_exec|popen|proc_open|create_function|call_user_func(_array)?)\s*\(\s*(@?(stripslashes|base64_decode|urldecode|rawurldecode|str_rot13|gzinflate)\s*\(\s*)*@?\$_(GET|POST|REQUEST|COOKIE|SERVER)|\$_(GET|POST|REQUEST|COOKIE)\s*\[[^]]+\]\s*\()' '*.php'

  # Cloaking: visitors are told apart by referrer (came from Google), user
  # agent (Googlebot, iPhone) or Google's crawler IPs, and only that group is
  # redirected / shown injected content, so the site owner on a desktop never
  # sees it. The regex only finds where the referrer / user agent is READ;
  # rate_CLOAKING reads the code around it (multi-line: real cloakers store
  # it in a variable first) and reports only when it is tested for search
  # engines/bots/mobile AND an action follows (redirect, injected script or
  # link, remote content). A condition alone (cache, SEO, analytics,
  # wp_is_mobile) is clean.
  register_check CLOAKING high none \
    $'HTTP_USER_AGENT\nHTTP_REFERER\ndocument.referrer\nnavigator.userAgent' \
    "Cloaking: search-engine/bot/mobile visitors redirected or served other content" \
    '(HTTP_(USER_AGENT|REFERER)|document\.referrer|navigator\.userAgent)' \
    '*.php' '*.js' '.htaccess'

  # Google's crawler IP ranges as string literals: code that recognises
  # Googlebot by IP to show it different content (plugins verify crawlers by
  # reverse DNS, not by hard-coded ranges). Separate check: in one alternation
  # with CLOAKING perl loses its literal optimisations (10x slower).
  register_check CLOAKING_BOT_IP high none \
    $'64.233.1\n66.249.\n66.102.\n72.14.\n74.125.\n209.85.\n216.239.' \
    "Hard-coded Googlebot IP ranges: content switched for Google's crawler" \
    "['\"](64\\.233\\.1[6-9][0-9]|66\\.249\\.(6[4-9]|[7-9][0-9])|66\\.102\\.[0-9]|72\\.14\\.(19[2-9]|2[0-5][0-9])|74\\.125\\.[0-9]|209\\.85\\.(1[2-9][0-9]|2[0-5][0-9])|216\\.239\\.(3[2-9]|[45][0-9]|6[0-3]))" \
    '*.php' '*.js'

  # Redirects of EVERY visitor to another domain, hard-coded where an
  # injection puts them (CLOAKING covers redirects aimed at a group). Generic
  # redirect code in plugin PHP/JS is not checked: plugins legitimately send
  # users to their own services (OAuth, upgrade pages); injected code there
  # is usually obfuscated and caught by the decoder checks.
  # .htaccess: RewriteRule / Redirect* / ErrorDocument to a literal domain.
  # rate_HTACCESS_REDIRECT skips canonical rules (force https / www).
  register_check HTACCESS_REDIRECT medium none $'RewriteRule\nRedirect\nErrorDocument' \
    ".htaccess sends visitors to another domain (RewriteRule/Redirect/ErrorDocument)" \
    'RewriteRule[ \t]+[^ \t]+[ \t]+https?://[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}([/ \t?]|$)|(^|[ \t])Redirect(Match|Permanent|Temp)?[ \t]+([^ \t]+[ \t]+){1,2}https?://[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}|ErrorDocument[ \t]+[0-9]{3}[ \t]+https?://[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}' \
    '.htaccess'

  # ---- signature lists: just add words (matched as whole words) ----------
  register_signatures WEBSHELL_MARKERS high \
    "Known webshell signatures (WSO/FilesMan, b374k, c99, r57, IndoXploit, Alfa)" '*.php' \
    FilesMan b374k c99shell r57shell IndoXploit WSOsetcookie wso_version 0byt3m1n1 AlfaTeam

  # Techniques, not names: what a shell does to escape disable_functions /
  # open_basedir or to read the server, never needed by a WordPress plugin.
  # Pairs of  PREFILTER-LITERAL  REGEX  (the literal must be part of every
  # match). Each one was checked against 69 plugins + 22 themes: 0 legit hits.
  # ini settings: only the bypass VALUE (/ or emptied + newline, as written
  # into .user.ini/php.ini), not messages like 'open_basedir = "%s"' (W3TC).
  # PHP_CHR_LIST also tests decoded chr() strings against this list.
  register_patterns WEBSHELL_TECHNIQUES high \
    "Webshell techniques: disable_functions/open_basedir bypass, reading system files" '*.php' \
    'LD_PRELOAD'     'LD_PRELOAD' \
    '__attribute__'  '__attribute__\s*\(\(\s*constructor' \
    'gcc'            'gcc\s+(-[A-Za-z0-9_=]+\s+)*-shared' \
    'nostartfiles'   '-nostartfiles' \
    'FFI::'          '(^|[^A-Za-z0-9_])FFI::(cdef|load|scope)\s*\(' \
    'pcntl_exec'     '(^|[^A-Za-z0-9_$>:])pcntl_exec([^A-Za-z0-9_]|$)' \
    'oProxyCommand'  '-oProxyCommand' \
    '/etc/'          '(file_get_contents|file|fopen|readfile|show_source|highlight_file|copy|symlink)\s*\(\s*@?['\''"]/etc/(passwd|shadow)['\''"]' \
    '/etc/shadow'    '/etc/shadow' \
    'open_basedir'   'open_basedir\s*=\s*(/\s*)?\\n|open_basedir\s*=\s*/\s*['\''"]' \
    'open_basedir'   'php_value\s+open_basedir\s+(/|none)\s*(\\n|['\''"])' \
    'disable_functions' 'disable_functions\s*=\s*(none\s*)?\\n|disable_functions\s*=\s*none\s*['\''"]' \
    'Chankro'        '(^|[^A-Za-z0-9_])Chankro([^A-Za-z0-9_]|$)' \
    'bypass_disablefunc' 'bypass_disablefunc'

  # Names spelled one character at a time ('F'.'F'.'I' = FFI) so a plain
  # search for the name finds nothing. Same quote type, no or single spaces
  # (one literal per form, for the prefilter).
  register_patterns PHP_SPLIT_STRING medium \
    "Name spelled char by char from 3+ one-letter strings ('F'.'F'.'I')" '*.php' \
    "'.'"   "'[A-Za-z_]'(\.'[A-Za-z_]'){2,}" \
    "' . '" "'[A-Za-z_]'( \. '[A-Za-z_]'){2,}" \
    '"."'   '"[A-Za-z_]"(\."[A-Za-z_]"){2,}' \
    '" . "' '"[A-Za-z_]"( \. "[A-Za-z_]"){2,}'

  # PHP char-code lists: array_map('chr', [76,68,...]) / chr(115).chr(121)...
  # rate_PHP_CHR_LIST decodes them: binary bytes (fonts, barcodes, magic
  # numbers) are skipped, text that hits WEBSHELL_TECHNIQUES or names a
  # dangerous function -> HIGH.
  register_check PHP_CHR_LIST medium charcodes $'chr(\nchr (\n\'chr\'\n"chr"' \
    "Text hidden as PHP character codes: array_map('chr', [..]) or chr(n).chr(n).." \
    'array_map\s*\(\s*('\''chr'\''|"chr")\s*,\s*(\[|array\s*\()\s*(0x[0-9a-fA-F]{1,2}|[0-9]{1,3})(\s*,\s*(0x[0-9a-fA-F]{1,2}|[0-9]{1,3})){3,}|(chr ?\(\s*(0x[0-9a-fA-F]{1,2}|[0-9]{1,3})\s*\)\s*\.\s*){3,}chr ?\(\s*(0x[0-9a-fA-F]{1,2}|[0-9]{1,3})\s*\)' '*.php'


  # ---- medium: suspicious, occasionally legitimate -------------------------
  register_check BASE64_LITERAL medium base64 $'atob\nbase64_decode' \
    "atob()/base64_decode() on a long hard-coded literal" \
    '(atob|base64_decode)\(\s*['\''"][A-Za-z0-9+/=]{20,}'

  # A bare base64 string that IS a URL (stored, decoded elsewhere). Only the
  # token-start prefixes: aHR0cHM6Ly = https://, aHR0cDovL = http://. URLs
  # inside bigger blobs (other alignments) and SVG data URIs (PHN2Zy, PD94)
  # are left out: too noisy. atob('aHR0..') itself is BASE64_LITERAL.
  register_check BASE64_URL medium b64url $'aHR0cHM6Ly\naHR0cDovL' \
    "Base64-encoded URL (aHR0cHM6Ly = https://): hidden link decoded at runtime" \
    '(^|[^A-Za-z0-9+/])(aHR0cHM6Ly|aHR0cDovL)[A-Za-z0-9+/_-]{8,}'

  register_check FROMCHARCODE_LIST medium charcodes 'fromCharCode' \
    "fromCharCode() with a short numeric list (6-29 chars)" \
    'fromCharCode\(\s*[0-9]{2,3}(\s*,\s*[0-9]{2,3}){5,28}\s*\)'

  # Printable escapes only (\x20-\x7e, \x9 \xa \xd): hidden text/char tables.
  # Binary constants (crypto keys: \xed\xd3...\x00) are not matched.
  register_check HEX_BLOB medium none '\x' \
    "Long run of printable \\xNN escapes (30+): hidden string/char table" \
    '(\\x([2-7][0-9a-fA-F]|0?[9aAdD])){30,}'

  # Used by some old legit libraries (LayerSlider, GreenSock) -> LOW
  register_check JS_PACKER low none 'eval' \
    "Dean Edwards packer eval(function(p,a,c,k,e,d))" \
    'eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)'

  register_check JS_OBFUSCATOR medium none '_0x' \
    "javascript-obfuscator style identifiers (_0x1a2b3c)" \
    '_0x[0-9a-f]{4,6}[^_0-9a-z]{1,4}_0x[0-9a-f]{4,6}[^_0-9a-z]{1,4}_0x[0-9a-f]{4,6}'

  # ---- disguised files ----------------------------------------------------
  # Image extension but no image data (PHP/HTML saved as .jpg, included or
  # served from elsewhere), or a real image with PHP code inside. Every image
  # is read by classify_FAKE_IMAGE; real, clean images are not listed.
  register_file_check FAKE_IMAGE high \
    "Image files that are really PHP/HTML, or images with PHP code inside" \
    '*.jpg|*.jpeg|*.png|*.gif|*.ico|*.webp|*.bmp'

  # ---- exposed files (listed after malicious-code findings) ---------------
  register_file_check EXPOSED_WPCONFIG high \
    "wp-config copies not ending in .php (DB credentials)" \
    'wp-config*' '*.php'

  # .php followed by a separator (.php.bak .php-bak .php_bkup .php~ .php.gz)
  # or a backup word glued on (.phpbak .phpold). Not: .phpunit/.phpcs/.phps
  # (different word), *.php (still runs), *.php5/7 (still runs).
  register_file_check EXPOSED_PHP high \
    "Renamed/backup PHP files (x.php.bak) that may be served as source" \
    '*.php[!a-zA-Z]*|*.phpbak*|*.phpbk*|*.phpbkp*|*.phpold*|*.phporig*|*.phpsave*|*.phpsav*|*.phpswp*|*.phpbackup*|*.phpcopy*|*.phptmp*|*.phptxt*' \
    '*.php' '*.php[0-9]'

  register_file_check UPLOADS_PHP high \
    "Executable PHP inside wp-content/uploads" \
    '*/wp-content/uploads/*.php'

  # WordPress's own layout, not a list of bad names: in a WP root (has
  # wp-settings.php + wp-includes/) and in its wp-content/ only a fixed set
  # of core files / drop-ins exists. Anything else there is a planted file.
  register_file_check ROOT_PHP_UNKNOWN medium \
    "Unknown PHP file in the WordPress root or wp-content/ (not core, not a drop-in)" \
    '*.php'

  # ---- low: broad safety net -----------------------------------------------
  register_check CHARCODE_ARITH low none 'charCodeAt' \
    "charCodeAt() arithmetic / XOR with a small constant (broad)" \
    'charCodeAt\([^)]*\)\s*[-+^]\s*[0-9]{1,3}([^0-9]|$)'
}

# -----------------------------------------------------------------------------
#  ALLOWLIST — known-legit files, hidden from the results (still counted)
#
#  allow 'PATH_REGEX' 'CHECK,CHECK' | 'all'  "reason"
#    PATH_REGEX matches the path relative to the scan dir. Scope rules to
#    specific checks so signature checks still apply to those files.
# -----------------------------------------------------------------------------
register_allowlist() {
  allow '(^|/)plugins/wordfence/' 'CHARCODE_SHIFT,CHARCODE_ARITH,BASE64_LITERAL,FROMCHARCODE_LIST' \
    "Wordfence bundles legit charcode/base64 code"
  allow '(^|/)plugins/superb-(blocks|helper-pro)/.*reveal-button(/index)?\.js$' 'CHARCODE_SHIFT,CHARCODE_ARITH' \
    "Superb Reveal Button: btoa + charCode +/-1 on the block's own data-reveal text"
  allow '(^|/)simpletest/tests/upgrade/[^/]*\.database\.php\.gz$' 'EXPOSED_PHP' \
    "Drupal core upgrade-test fixtures (generic sample DBs)"
}

# -----------------------------------------------------------------------------
#  FILE CLASSIFIERS — classify_<ID>: newline file list on stdin,
#  print "sev<TAB>note<TAB>file" per file.
# -----------------------------------------------------------------------------
# Severities: high | medium | low, "skip" = not a real finding (counted
# with the allowlisted files, reason shown with -v), or "ok" = clean, not
# listed or counted at all (for checks that look at every file of a type).
classify_EXPOSED_PHP() {
  perl -ne '
    chomp; my $f = $_; next unless length $f;
    if ($f =~ /\.(gz|bz2|xz|zip|tar|tgz|7z|rar)$/i) {
      print "medium\tcompressed, downloadable - check contents\t$f\n"; next }
    my $sz = -s $f;
    if (!$sz) { print "low\tempty file\t$f\n"; next }
    my $c = ""; if (open(my $h, "<", $f)) { read($h, $c, 262144); close $h }
    # Shipped templates/samples/tool configs (x.php.in, x.php.dist,
    # x.php_example, .php_cs.dist) are not backups of live files: skip them
    # unless they hold credentials or code a webshell needs.
    if ($f =~ /\.php([._-](in|dist|example|sample|tpl)|_cs|-cs-fixer)(\.dist)?$/i
        && $c !~ /DB_PASSWORD|DB_USER|AUTH_KEY|\beval\s*\(|\bassert\s*\(|base64_decode|gzinflate|str_rot13|\$_(GET|POST|REQUEST|COOKIE|FILES)|\b(system|exec|passthru|shell_exec|popen|proc_open)\s*\(/i) {
      print "skip\tshipped template/sample/tool config, no credentials or exec code\t$f\n"; next }
    if ($c =~ /<\?(php|=)/i) { print "high\tcontains PHP code\t$f\n"; next }
    my $head = substr($c, 0, 2048);
    my $bin  = $head =~ /\x00/ || $head =~ /^(\x89PNG|GIF8|\xff\xd8)/;
    my $html = $head =~ /<!doctype|<html/i;
    my $url  = $f =~ /\.php[^\/]*=/i;            # saved URL with ?query
    if ($html || $bin || $url) {
      print "skip\tsaved page/image (no PHP code), not a renamed PHP file\t$f\n" }
    else { print "low\tno PHP code\t$f\n" }'
}

# Magic bytes decide what a file is, not its extension (a PNG named .jpg is
# common and fine). '<?=' is only trusted in text: 3 bytes turn up by chance
# in binary image data. Real images are only checked for '<?php'.
# Speed: sites hold 10k-200k images, so only the first 256 KB and the last
# 64 KB of a file are read (fake images start with the code; polyglots carry
# it in EXIF/comment blocks near the start or appended at the end). Known
# limit: PHP placed in the middle of a large image's pixel data is missed.
classify_FAKE_IMAGE() {
  HEADB=262144 TAILB=65536 perl -ne '
    chomp; my $f = $_; next unless length $f;
    my $sz = -s $f;
    if (!$sz) { print "low\tempty image file\t$f\n"; next }
    my ($c, $t) = ("", "");
    if (open(my $h, "<:raw", $f)) {
      read($h, $c, $ENV{HEADB});
      if ($sz > $ENV{HEADB} + $ENV{TAILB}) { seek($h, -$ENV{TAILB}, 2); read($h, $t, $ENV{TAILB}) }
      elsif ($sz > $ENV{HEADB}) { read($h, $t, $ENV{TAILB}) }
      close $h; $c .= "\n$t" if length $t;
    } else { print "ok\tunreadable\t$f\n"; next }
    my $img = $c =~ /\A(\xff\xd8\xff|\x89PNG\r\n\x1a\n|GIF8[79]a|\x00\x00[\x01\x02]\x00|RIFF....WEBP|BM|II\x2a\x00|MM\x00\x2a|....ftyp)/s;
    my $head = substr($c, 0, 4096);
    my $text = $head !~ /\x00/;
    if ($img) {
      if ($c =~ /<\?php/i) { print "high\timage with PHP code inside (polyglot)\t$f\n" }
      else                 { print "ok\treal image\t$f\n" }
    } elsif ($c =~ /<\?php/i || ($text && $c =~ /<\?=/)) {
      print "high\tPHP code disguised as an image (no image data)\t$f\n";
    } elsif ($text && $head =~ /\A\s*(<\?xml[^>]*>\s*)?(<!--.*?-->\s*|<!DOCTYPE\s+svg[^>]*>\s*)*<svg[\s>]/is) {
      # SVG named .png (design-tool exports, e.g. CF7 Honeypot icons): fine
      # unless it carries scripts, handlers or links (embedded data:image ok)
      if ($c =~ /<(script|foreignObject|iframe|html|body|meta|a)[\s>]|javascript:|\bon[a-z]+\s*=|(href|src)\s*=\s*["\x27]?\s*(https?:|\/\/|data:(?!image\/))/i) {
        print "medium\tSVG with scripts/links disguised as an image\t$f\n" }
      else { print "ok\tplain SVG with a bitmap extension\t$f\n" }
    } elsif ($text && $head =~ /<(!doctype|html|head|body|script|iframe|meta)[\s>]/i) {
      print "medium\tHTML page disguised as an image (no image data)\t$f\n";
    } elsif ($text) {
      print "medium\ttext file disguised as an image (no image data)\t$f\n";
    } else { print "ok\tother binary format\t$f\n" }'
}

# Core root files of WordPress and the wp-content drop-ins (all versions
# since 3.x). Dirs that are not a WP root / wp-content are not judged.
# wordfence-waf.php (Wordfence "optimized" WAF loader, very common) is
# skipped only while it holds nothing but its own include of the WAF.
classify_ROOT_PHP_UNKNOWN() {
  perl -ne '
    BEGIN {
      %core = map { $_ => 1 } qw(index.php wp-activate.php wp-blog-header.php
        wp-comments-post.php wp-config.php wp-config-sample.php wp-cron.php
        wp-links-opml.php wp-load.php wp-login.php wp-mail.php wp-settings.php
        wp-signup.php wp-trackback.php xmlrpc.php);
      %dropin = map { $_ => 1 } qw(index.php advanced-cache.php object-cache.php
        db.php db-error.php install.php maintenance.php php-error.php
        fatal-error-handler.php sunrise.php blog-deleted.php blog-inactive.php
        blog-suspended.php);
    }
    chomp; my $f = $_; next unless length $f;
    my ($d, $b) = $f =~ m{^(?:(.*)/)?([^/]+)$}; $d = "." unless defined $d;
    $root{$d} //= (-f "$d/wp-settings.php" && -d "$d/wp-includes") ? 1 : 0;
    if (!exists $wpc{$d}) {
      my ($p, $n) = $d =~ m{^(?:(.*)/)?([^/]+)$}; $p = "." unless defined $p;
      $wpc{$d} = ($n eq "wp-content" && -f "$p/wp-settings.php") ? 1 : 0;
    }
    if    ($root{$d} && !$core{lc $b}) { $where = "WordPress root" }
    elsif ($wpc{$d}  && !$dropin{lc $b}) { $where = "wp-content/" }
    else  { print "ok\tknown core file / drop-in, or not a WP root\t$f\n"; next }
    if ($root{$d} && lc $b eq "wordfence-waf.php") {
      my $c = ""; if (open(my $h, "<", $f)) { local $/; $c = <$h>; close $h }
      $c =~ s{/\*.*?\*/}{}gs; $c =~ s{(^|\s)(//|\#)[^\n]*}{$1}g; $c =~ s{<\?php|\?>}{}g;
      $c =~ s{if\s*\(\s*file_exists\s*\(\s*__DIR__\s*\.\s*[\x27"]/wp-content/plugins/wordfence/waf/bootstrap\.php[\x27"]\s*\)\s*\)}{}g;
      $c =~ s{define\s*\(\s*[\x27"]WFWAF_LOG_PATH[\x27"]\s*,\s*__DIR__\s*\.\s*[\x27"]/wp-content/wflogs/[\x27"]\s*\)\s*;}{}g;
      $c =~ s{include_once\s*\(?\s*__DIR__\s*\.\s*[\x27"]/wp-content/plugins/wordfence/waf/bootstrap\.php[\x27"]\s*\)?\s*;}{}g;
      $c =~ s{[\s{}]+}{}g;
      if ($c eq "") { print "skip\tWordfence WAF loader (only includes the Wordfence WAF)\t$f\n"; next }
    }
    print "medium\tunknown PHP file in the $where\t$f\n";'
}

classify_EXPOSED_WPCONFIG() {
  local f; local -a files; declare -A has
  mapfile -t files
  printf '%s\0' "${files[@]}" | xargs -0 -r grep -lIE 'DB_PASSWORD|DB_USER' -- 2>/dev/null \
    | while IFS= read -r f; do has[$f]=1; done
  for f in "${files[@]}"; do
    if [[ -n ${has[$f]} ]]; then printf 'high\tCONTAINS DB CREDENTIALS\t%s\n' "$f"
    else printf 'medium\tno credentials found inside\t%s\n' "$f"; fi
  done
}

# Placeholder = only status headers / http_response_code / exit / die /
# comments (e.g. "Silence is golden", WPForms 404 index.php). Anything else,
# including a Location: redirect, is real code.
classify_UPLOADS_PHP() {
  perl -ne '
    chomp; my $f = $_; next unless length $f;
    my $sz = -s $f;
    if (!$sz) { print "low\tempty file\t$f\n"; next }
    if ($sz > 4096) { print "high\texecutable PHP in uploads\t$f\n"; next }
    my $c = ""; if (open(my $h, "<", $f)) { local $/; $c = <$h>; close $h }
    $c =~ s{/\*.*?\*/}{}gs;  $c =~ s{(^|\s)(//|\#)[^\n]*}{$1}g;
    $c =~ s{<\?(php|=)?|\?>}{}gi;
    $c =~ s{\bheader\s*\(\s*\$_SERVER\s*\[\s*[\x27"]SERVER_PROTOCOL[\x27"]\s*\][^;]*\)\s*;}{}gi;
    $c =~ s{\bheader\s*\(\s*[\x27"](HTTP/[0-9.]+\s+[0-9]{3}|Status:\s*[0-9]{3})[^;]*\)\s*;}{}gi;
    $c =~ s{\bhttp_response_code\s*\(\s*[0-9]{3}\s*\)\s*;}{}gi;
    $c =~ s{\b(exit|die)\s*(\(\s*\))?\s*;?}{}gi;
    $c =~ s{\s+}{}g;
    if ($c eq "") { print "skip\tplaceholder index (only blocks access, no code)\t$f\n" }
    else          { print "high\texecutable PHP in uploads\t$f\n" }'
}

# -----------------------------------------------------------------------------
#  MATCH RATERS — rate_<ID>: all matches of the check on stdin, one per line
#  "pre US match US post US file US line" (US = \x1f; pre/post = CTX_BEFORE/
#  CTX_AFTER chars around it; file/line to read more code when needed). For a
#  match whose severity changes print "N<TAB>sev<TAB>note" (N = input line
#  number, $.); print nothing to keep it. sev "skip" = not a finding (listed
#  as ignored), "ok" = clean (not listed). Use `next`, never `exit`. Judge
#  the CONTENT, never the path or package: a skip must hold for any file. A
#  file is ignored only if every match in it is rated skip.
#  Every rule needs a malicious look-alike in tests/samples (see HANDOVER.md).
# -----------------------------------------------------------------------------
# Real text/code of 30+ chars always repeats characters; a run where every
# byte is distinct is a lookup table (e.g. symfony Normalizer $ASCII). Using
# such a table to build code is caught by PHP_CHAR_ASSEMBLY.
rate_HEX_BLOB() {
  perl -ne '
    chomp; my (undef, $m) = split /\x1f/;
    my @c = map { hex } $m =~ /\\x([0-9a-fA-F]{1,2})/g; my %u; @u{@c} = ();
    print "$.\tskip\tcharacter lookup table (all ", scalar @c, " chars distinct), not hidden text\n"
      if @c >= 30 && keys %u == @c;'
}

# Decode the literal. Skip a plain image (tracking pixel, icon) unless code
# is hidden in it (GIF89a<?php ... trick), and a short opaque ID/key: only
# letters+digits, both present, 12-40 chars, so it can't be a URL, a PHP
# function name (those need _ or are shorter) or code.
rate_BASE64_LITERAL() {
  (( HAVE_B64 )) || { cat >/dev/null; return 0; }
  perl -MMIME::Base64 -ne '
    chomp; my (undef, $m) = split /\x1f/;
    my ($b) = $m =~ /([A-Za-z0-9+\/=]{20,})$/ or next;
    my $d = decode_base64($b);
    if ($d =~ /^(GIF8[79]a|\x89PNG\r\n|\xff\xd8\xff|RIFF....WEBP)/s
        && $d !~ /<\?|<script|eval|base64|\$_|function/i) {
      print "$.\tskip\tembedded image (", length $d, " bytes), no code inside\n" }
    elsif ($d =~ /^[A-Za-z0-9]{12,40}$/ && $d =~ /[A-Za-z]/ && $d =~ /[0-9]/) {
      print "$.\tskip\topaque ID/key (", length $d, " chars), not code or a URL\n" }'
}

# Ordinary character maths, not a char-shift decoder. A real shift (+/-1..25
# whose result is used) still matches; anything fed straight into
# fromCharCode() is CHARCODE_SHIFT (HIGH, no rater).
rate_CHARCODE_ARITH() {
  perl -ne '
    chomp; my ($p, $m, $q) = split /\x1f/; $q //= "";
    my ($idx, $op, $n, $rest) = $m =~ /^charCodeAt\(([^)]*)\)\s*([-+^])\s*([0-9]+)(.*)$/ or next;
    my $after = $rest . $q;
    my $why =
      ($op eq "-" && $n =~ /^(32|48|55|64|65|87|96|97)$/)
        ? "ASCII anchor -$n (digit/letter to number)"
      : $p =~ /[\x27"].[\x27"]\.$/                       ? "maths on a char literal (\"A\".charCodeAt)"
      : $after =~ /^\s*(===?|!==?|<=?|>=?)/              ? "compared, not turned into a character"
      : $idx =~ /\(/                                     ? "arithmetic on the index, not the char code"
      : ($op eq "+" && $n == 1 && $idx eq "0" && $q =~ /^.{0,40}charCodeAt\(0\)\s*-\s*1(?![0-9])/)
     || ($op eq "-" && $n == 1 && $idx eq "0" && $p =~ /charCodeAt\(0\)\s*\+\s*1[^0-9].{0,40}$/)
                                                          ? "character-range bounds (a-z expansion)"
      : "";
    print "$.\tskip\t$why\n" if $why;'
}

# Copying array elements in order ($c['col'][1].$c['col'][2].$c['col'][3]...,
# mPDF colours) is not char-picking: spelling hidden code from a lookup table
# jumps around it ($t['k'][77].$t['k'][40]...). Skip only when every index is
# exactly the previous one + 1.
rate_PHP_CHAR_ASSEMBLY() {
  perl -ne '
    chomp; my (undef, $m) = split /\x1f/;
    my @i = $m =~ /\[([0-9]{1,3})\](?=\s*(?:\.|$))/g;
    my $seq = @i >= 4; for my $k (1 .. $#i) { $seq = 0 if $i[$k] != $i[$k-1] + 1 }
    print "$.\tskip\tconsecutive array elements copied in order ($i[0]..$i[-1]), not char-picking\n" if $seq;'
}

# CLOAKING found a read of the referrer / user agent. Who is targeted = the
# engine/bot/mobile/social words near it (that line + 3 lines; minified: 400
# chars). No words -> ok. Then look for an action after it: 12 lines, or 40
# for referrer + search engine (strongest sign; then any remote fetch counts,
# e.g. curl to a URL built from variables). Minified JS: next 600 chars.
#   referrer / search engine / bot / social app + any action   -> HIGH
#   mobile only + action to a hard-coded URL                    -> HIGH
#   mobile only + action without a URL (menus, iOS tap fixes)   -> ok
#   NOT-bot (!preg_match(bot)) + only printed output (analytics) -> ok
#   no action                                                   -> ok
rate_CLOAKING() {
  perl -ne '
    BEGIN { our ($cf, @L) = ("") }
    chomp; my $n = $.;             # $. is reset when the source file is read
    my ($p, $m, $q, $f, $l) = split /\x1f/;
    if ($f ne $cf) { $cf = $f; @L = (); if (open(my $h, "<", $f)) { @L = <$h>; close $h } }
    my $line = $L[$l - 1] // ""; chomp $line;
    my $at = index($line, $m); $at = 0 if $at < 0;
    my $min = length($line) > 2000;
    my $near = $min ? substr($line, ($at > 200 ? $at - 200 : 0), 600)
                    : join(" ", $line, map { $L[$_] // "" } $l .. $l + 2);
    my @w = map { lc } $near =~ /(google|bing|yahoo|yandex|baidu|duckduck|bot|crawl|spider|slurp|android|iphone|ipad|ipod|mobile|facebook|twitter|instagram|tiktok)/gi;
    my %u; @w = grep { !$u{$_}++ } @w;
    if (!@w) { print "$n\tok\treferrer/user agent not tested for bots, engines or mobile\n"; next }
    my $who = $m =~ /REFERER|referrer/ ? "referrer" : "user agent";
    my $strong = $who eq "referrer" && grep { /^(google|bing|yahoo|yandex|baidu|duckduck)$/ } @w;
    my $scope = substr($line, $at);
    if ($min) { $scope = substr($scope, 0, 600 + length $m) }
    else { my $n = $strong ? 40 : 12;
           for my $k ($l .. $l + $n - 1) { last if $k > $#L || length($scope) > 8000; $scope .= " " . $L[$k] } }
    my $mobile = !grep { !/^(android|iphone|ipad|ipod|mobile)$/ } @w;
    my $notbot = $who eq "user agent" && $p =~ /!\s*(preg_match|strpos|stripos|stristr|strstr)\s*\([^)]*$/i;
    my $ext = $f =~ /\.js$/i ? "js" : $f =~ /htaccess$/i ? "ht" : "php";
    my ($act, $out) = ("", 0);
    if ($ext eq "ht") {
      $act = "RewriteRule to an external URL" if $scope =~ /RewriteRule\s+\S+\s+https?:\/\//i }
    elsif ($ext eq "js") {
      $act = $scope =~ /\blocation\.(replace|assign)\s*\(|\blocation(\.href)?\s*=(?!=)/ ? "redirect (location)"
           : $scope =~ /\bwindow\.open\s*\(/                                         ? "popup (window.open)"
           : $scope =~ /createElement\s*\(\s*[\x27"]script|document\.write\s*\(/      ? "script injected"
           : $scope =~ /\b(eval|atob)\s*\(|fromCharCode/                              ? "decoded/evaluated code"
           : "" }
    else {
      $act = $scope =~ /header\s*\(\s*[\x27"]\s*Location\s*:/i                        ? "redirect (header Location)"
           : $scope =~ /\bwp_(safe_)?redirect\s*\(/                                   ? "redirect (wp_redirect)"
           : $scope =~ /(include|require)(_once)?\s*\(?\s*[\x27"]https?:/i             ? "remote include"
           : $scope =~ /\b(file_get_contents|curl_init|fopen|readfile|wp_remote_get|fsockopen)\s*\([^;]{0,120}https?:/i ? "remote content fetched"
           : $scope =~ /\b(eval|assert|base64_decode|gzinflate|str_rot13)\s*\(/       ? "decoded/evaluated code"
           : $scope =~ /http-equiv\s*=\s*.?refresh|location\.(href|replace)/i         ? "redirect (meta refresh / JS)"
           : $strong && $scope =~ /\b(curl_init|curl_exec|file_get_contents|fsockopen|stream_socket_client)\s*\(/i ? "remote content fetched"
           : "";
      if (!$act && $scope =~ /\b(echo|print|printf)\b[^;]{0,300}(<script|<iframe|<a\s[^>]{0,80}href)/i) {
        $act = "links/script printed"; $out = 1 } }
    my ($url) = $scope =~ m{(?:https?:)?//([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.[a-z]{2,})}i;
    my $tgt = "visitors by $who (" . join(",", @w[0 .. ($#w < 3 ? $#w : 3)]) . ")";
    if (!$act)                     { print "$n\tok\tno redirect/injection after the check\n" }
    elsif ($mobile && !$url)       { print "$n\tok\tmobile check, no hard-coded target URL\n" }
    elsif ($notbot && $out)        { print "$n\tok\toutput for non-bots only (analytics)\n" }
    else                           { print "$n\thigh\t$tgt get: $act", ($url ? " -> $url" : ""), "\n" }'
}

# A RewriteRule whose own RewriteCond block (the conditions directly above
# it; Apache applies them to that one rule only) tests the scheme/port
# (force https) or an HTTP_HOST naming the same domain it redirects to
# (www <-> non-www) is the site's own canonical rule -> ok. Anything else,
# incl. Redirect/ErrorDocument (no conditions): MED + target host.
rate_HTACCESS_REDIRECT() {
  perl -ne '
    BEGIN { our ($cf, @L) = ("") }
    chomp; my $n = $.;                 # $. is reset when the source file is read
    my ($p, $m, $q, $f, $l) = split /\x1f/;
    my ($host) = $m =~ m{https?://([A-Za-z0-9.-]+)}; $host = lc $host;
    if ($f ne $cf) { $cf = $f; @L = (); if (open(my $h, "<", $f)) { @L = <$h>; close $h } }
    # only the RewriteCond block directly above THIS rule applies to it
    my $cond = "";
    if ($m =~ /^RewriteRule/) {
      for (my $k = $l - 2; $k >= 0; $k--) {
        my $x = $L[$k]; next if $x =~ /^\s*(#|$)/;
        last unless $x =~ /^\s*RewriteCond\b/i; $cond .= $x } }
    (my $base = $host) =~ s/^www\.//; (my $re = quotemeta $base) =~ s/\\\./\\\\?\\./g;
    if ($cond =~ /RewriteCond\s+%\{(HTTPS|SERVER_PORT|HTTP:X-Forwarded-Proto|REQUEST_SCHEME)\}/i
        || ($cond =~ /RewriteCond\s+%\{HTTP_HOST\}\s+(\S+)/i && $1 =~ /$re/i)) {
      print "$n\tok\tcanonical https/www rule for the site itself\n"; next }
    print "$n\tmedium\tall visitors redirected -> $host\n";'
}

# Decode the list. Binary bytes (any outside printable ASCII/tab/newline) =
# font tables, barcodes, file magic: skip. Text that WEBSHELL_TECHNIQUES
# matches, or that names a code-running function, or 20+ chars -> HIGH.
rate_PHP_CHR_LIST() {
  TECH_RE=${CHECK_RE[WEBSHELL_TECHNIQUES]} perl -ne '
    chomp; my (undef, $m) = split /\x1f/;
    my @n = $m =~ /(?:^|[\[(,.]|chr\s*\()\s*(0x[0-9a-fA-F]{1,2}|[0-9]{1,3})(?=\s*[,\])]|$)/g;
    my $d = join "", map { chr(/^0x/i ? hex : $_) } @n;
    if ($d =~ /[^\x09\x0a\x0d\x20-\x7e]/) { print "$.\tskip\tbinary bytes (font/barcode/file magic), not text\n"; next }
    (my $show = $d) =~ s/\s+/ /g; $show = substr($show, 0, 40);
    if ((length $ENV{TECH_RE} && $d =~ /$ENV{TECH_RE}/)
        || $d =~ /^(eval|assert|system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec|create_function|call_user_func(_array)?|base64_decode|gzinflate|str_rot13|file_put_contents|fwrite|move_uploaded_file|putenv|mail|FFI|ini_set|ini_restore|dl)$/i) {
      print "$.\thigh\tdecodes to \"$show\"\n" }
    elsif (length $d >= 20) { print "$.\thigh\tdecodes to \"$show\" (20+ chars of hidden text)\n" }
    else { print "$.\tmedium\tdecodes to \"$show\"\n" }'
}

# -----------------------------------------------------------------------------
#  DECODERS — read a code window on stdin, print one decoded string per line
# -----------------------------------------------------------------------------
decode_none() { cat >/dev/null; }

decode_caesar() {
  perl -ne '
    my ($s, %seen);
    if (/charCodeAt\([^)]*\)\s*([-+])\s*(\d{1,2})(?!\d)/) { $s = $1 eq "-" ? $2 : -$2 }
    s/[\x27"`]\s*\+\s*[\x27"`]//g;            # join 'a'+'b'
    for my $seg (split /[\x27"`]/) {
      next if length($seg) < 6;
      for my $n (defined $s ? ($s) : (), -25..-1, 1..25) {
        my $d = join "", map { chr(ord($_) - $n) } split //, $seg;
        next if $d =~ /[^\x20-\x7e]/ || $seen{$d};
        my $ok = $d =~ m{^https?://[a-z0-9-]+\.}i
              || (defined $s && $n == $s && ($d =~ m{^//[a-z0-9-]+\.}i
                  || $d =~ m{^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}/}i));
        if ($ok) { $seen{$d} = 1; print "$d\n" }
      }
    }'
}

decode_base64() {
  (( HAVE_B64 )) || { cat >/dev/null; return 0; }
  perl -MMIME::Base64 -ne '
    while (/(?:atob|base64_decode)\(\s*([\x27"])([A-Za-z0-9+\/=]{8,})\1/g) {
      my $d = decode_base64($2);
      next unless $d =~ /^[\x20-\x7e\t\r\n]+$/;
      $d =~ s/\s+/ /g; print substr($d, 0, 300), "\n";
    }'
}

decode_b64url() {  # bare base64 tokens that start with http(s):// (also URL-safe -_)
  (( HAVE_B64 )) || { cat >/dev/null; return 0; }
  perl -MMIME::Base64 -ne '
    while (/(?<![A-Za-z0-9+\/])((?:aHR0cHM6Ly|aHR0cDovL)[A-Za-z0-9+\/_-]{8,}=*)/g) {
      (my $t = $1) =~ tr{-_}{+/};
      my $d = decode_base64($t); $d =~ s/[^\x20-\x7e].*//s;
      print substr($d, 0, 300), "\n" if length $d > 8;
    }'
}

decode_charcodes() {
  perl -ne '
    while (/fromCharCode\(\s*((?:\d{2,3}\s*,\s*){3,}\d{2,3})\s*\)?/g) {
      my $d = join "", map { chr } split /\s*,\s*/, $1;
      $d =~ s/[\x00-\x1f\x7f-\xff]+/ /g; print substr($d, 0, 300), "\n";
    }
    # PHP: array_map("chr", [n, ...]) and chr(n).chr(n)...
    my $num = qr/0x[0-9a-fA-F]{1,2}|[0-9]{1,3}/;
    my @lists;
    push @lists, $1 while /array_map\s*\(\s*[\x27"]chr[\x27"]\s*,\s*(?:\[|array\s*\()\s*((?:(?:$num)\s*,\s*){3,}(?:$num))/g;
    push @lists, $1 while /((?:chr\s*\(\s*(?:$num)\s*\)\s*\.\s*){3,}chr\s*\(\s*(?:$num)\s*\))/g;
    for my $l (@lists) {
      $l =~ s/chr\s*\(//g;
      my $d = join "", map { chr(/^0x/i ? hex : $_) } $l =~ /($num)/g;
      $d =~ s/[\x00-\x1f\x7f-\xff]+/ /g; print substr($d, 0, 300), "\n";
    }'
}

decode_hex() {
  perl -ne '
    while (/((?:\\x[0-9a-fA-F]{2}){4,})/g) {
      (my $h = $1) =~ s/\\x([0-9a-fA-F]{2})/chr hex $1/ge;
      $h =~ s/[\x00-\x1f\x7f-\xff]+/ /g; print substr($h, 0, 300), "\n";
    }'
}

decode_urlenc() {
  perl -ne '
    while (/unescape\s*\(\s*([\x27"])((?:%[0-9a-fA-F]{2}|[^\x27"]){8,}?)\1/g) {
      (my $d = $2) =~ s/%([0-9a-fA-F]{2})/chr hex $1/ge;
      $d =~ s/[\x00-\x1f\x7f-\xff]+/ /g; print substr($d, 0, 300), "\n";
    }'
}

shifted_scheme_literals() {  # http:// and https:// shifted by ±1..25
  perl -e 'for my $p ("https://", "http://") { for my $n (-25..-1, 1..25) {
    my $s = join "", map { chr(ord($_) + $n) } split //, $p;
    next if $s =~ /[^\x21-\x7e]|[\x27"`\\]/; print "$s\n" } }'
}

literals_to_regex() {  # newline list -> escaped ERE alternation
  printf '%s\n' "$1" | perl -ne 'chomp; next unless length; s/([.\[\]{}()*+?^\$|\\])/\\$1/g; push @a, $_;
    END { print join("|", @a) }'
}

# =============================================================================
#  ENGINE — normally no need to touch anything below
# =============================================================================
CHECK_IDS=()
declare -A CHECK_SEV CHECK_DEC CHECK_DESC CHECK_RE CHECK_INC CHECK_PRE CHECK_TYPE CHECK_EXCL
declare -A HIT_COUNT SUPP_COUNT SUPP_SEEN SUPP_FILES SUPP_WHY DOMAINS DECODED_SEEN SELECTED
declare -A REC_SEEN CF_SEV CF_LINES CF_NOTE CF_DEC CF_FILES CHECK_MAX FILE_SEV SHOWN FILE_CHECKS FILE_DEC
declare -A CF_PRE CF_MAT CF_POST CF_SLN FC_CLEAN
HIT_PRE=""; HIT_MAT=""; HIT_POST=""; SECTION_ORDER=(); SHOWN_CODE=""; WIDTH=140
declare -A SEV_RANK=([high]=3 [medium]=2 [low]=1)
CANDIDATES=(); ALLOW_RE=(); ALLOW_CHECKS=(); ALLOW_WHY=(); PRUNE=(); PRE_ARGS=()
STEP=0; STEPS=0; PROGRESS_DOTS=0; NO_DOTS=0; ALLOW_MATCH=""; NOW=0; ERRF=""
TMPD=""; HAVE_B64=1; WARNINGS=(); WATCH=()
KEEP=0; NO_COLOR=0; VERBOSE=0; VERIFY=0; SKIP_CORE=1; USE_ALLOW=1; REPORT=""; TARGET="."

die() {  # fatal error: clean up, explain, exit 2
  clear_line 2>/dev/null
  printf '%s[x] %s%s\n' "${RED:-}" "$*" "${RST:-}" >&2
  exit 2
}

cleanup() {  # remove our private temp dir (only ever one we created)
  [[ -n $TMPD && -d $TMPD && $TMPD == */fixed-malscan.* ]] && rm -rf -- "$TMPD"
  TMPD=""
}

on_signal() {
  clear_line 2>/dev/null
  printf '\n%s[x] Aborted - partial results discarded.%s\n' "${RED:-}" "${RST:-}" >&2
  exit 130
}

# Probe the exact features used (not version strings): if any is missing the
# scan would silently miss things, so stop instead.
require_tools() {
  local c missing=() t
  for c in grep find xargs perl stat sort comm paste sed head wc tee readlink \
           basename dirname date mktemp tr; do
    command -v "$c" >/dev/null 2>&1 || missing+=("$c")
  done
  (( ${#missing[@]} )) && die "Missing required command(s): ${missing[*]}"

  t=$(mktemp -d "${TMPDIR:-/tmp}/fixed-malscan.XXXXXX" 2>/dev/null) \
    || die "Cannot create a temp dir in ${TMPDIR:-/tmp} (set TMPDIR to a writable dir, e.g. TMPDIR=~/tmp)"
  TMPD=$t; ERRF="$TMPD/errors"; : > "$ERRF" || die "Cannot write to temp dir $TMPD"

  printf 'abc\n' > "$TMPD/probe.js"
  [[ $(grep -rlIF --include='*.js' --exclude-dir=x -e abc "$TMPD" 2>/dev/null) == "$TMPD/probe.js" ]] \
    || die "grep lacks GNU options (-r --include --exclude-dir -I). GNU grep is required."
  [[ $(printf 'a\0' | xargs -0 -r echo 2>/dev/null) == a ]] \
    || die "xargs lacks GNU options (-0 -r). GNU findutils is required."
  [[ $(find "$TMPD" -type f -iname 'PROBE.JS' -ipath '*/probe.js' -print 2>/dev/null) == "$TMPD/probe.js" ]] \
    || die "find lacks -iname/-ipath. GNU findutils is required."
  [[ $(stat -c %s -- "$TMPD/probe.js" 2>/dev/null) == 4 ]] \
    || die "stat lacks -c (GNU coreutils required)."
  rm -f -- "$TMPD/probe.js"
  perl -e 1 2>/dev/null || die "perl is installed but not working."
  if ! perl -MMIME::Base64 -e 1 2>/dev/null; then
    HAVE_B64=0; WARNINGS+=("perl MIME::Base64 missing: base64 strings are detected but not decoded")
  fi
}

# --watch / --watch-file: domains YOU supply for this run (nothing is built
# in). Matches go in their own "Watchlist" section, never in the HIGH list.
add_watch() {  # $1 = comma/space-separated domains
  local d IFS=$', \t'
  set -f
  for d in $1; do
    d=${d,,}; d=${d#http://}; d=${d#https://}; d=${d%%/*}; d=${d#.}
    [[ -n $d ]] || continue
    [[ $d =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] \
      || { set +f; die "Not a valid domain for --watch: $d"; }
    [[ " ${WATCH[*]} " == *" $d "* ]] || WATCH+=("$d")
  done
  set +f
}

add_watch_file() {  # one domain per line, '#' comments allowed
  local line
  [[ -f $1 && -r $1 ]] || die "Cannot read watch file: $1"
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%%#*}; add_watch "$line"
  done < "$1"
}

register_watchlist() {
  (( ${#WATCH[@]} )) || return 0
  register_signatures WATCHLIST medium \
    "Domains from your --watch list (supplied for this run, not built in)" \
    '*.js *.php *.html *.htm *.txt *.json' "${WATCH[@]}"
}

on_watchlist() {  # $1 domain: exact match or a subdomain of a watched one
  local w
  for w in "${WATCH[@]}"; do [[ $1 == "$w" || $1 == *".$w" ]] && return 0; done
  return 1
}

# Validate every registered check before scanning, so a typo in a new check
# stops the run instead of silently matching nothing.
validate_checks() {
  local id bad
  for id in "${CHECK_IDS[@]}"; do
    [[ ${CHECK_SEV[$id]} == @(high|medium|low) ]] || die "Check $id: bad severity '${CHECK_SEV[$id]}'"
    declare -F "decode_${CHECK_DEC[$id]}" >/dev/null || die "Check $id: no decoder decode_${CHECK_DEC[$id]}"
    [[ ${CHECK_TYPE[$id]} == content ]] || continue
    : | grep -E -- "${CHECK_RE[$id]}" >/dev/null 2>&1
    (( PIPESTATUS[1] == 2 )) && die "Check $id: regex rejected by grep -E"
  done
  bad=$(for id in "${CHECK_IDS[@]}"; do
          [[ ${CHECK_TYPE[$id]} == content ]] && printf '%s\t%s\n' "$id" "${CHECK_RE[$id]}"
        done | perl -ne 'chomp; my ($i, $r) = split /\t/, $_, 2; eval { qr/$r/ }; print "$i " if $@')
  [[ -z $bad ]] || die "Check(s) with a regex perl cannot compile: $bad"
}

# register_signatures ID SEVERITY "Description" 'GLOBS' word [word...]
# Plain strings matched as whole words (not inside longer letter/digit runs).
# Builds the prefilter and regex for you: just add or remove words.
register_signatures() {
  local id=$1 sev=$2 desc=$3 globs=$4; shift 4
  local words; words=$(printf '%s\n' "$@")
  local -a g; set -f; g=($globs); set +f
  register_check "$id" "$sev" none "$words" "$desc" \
    "(^|[^A-Za-z0-9])($(literals_to_regex "$words"))([^A-Za-z0-9]|\$)" "${g[@]}"
}

# register_patterns ID SEVERITY "Description" 'GLOBS' LITERAL REGEX [LITERAL REGEX...]
# A list of independent regexes, each with the prefilter literal it contains.
register_patterns() {
  local id=$1 sev=$2 desc=$3 globs=$4 lits="" re=""; shift 4
  (( $# % 2 == 0 )) || die "register_patterns $id: odd number of LITERAL REGEX args"
  while (( $# )); do
    lits+="$1"$'\n'; re+="${re:+|}($2)"; shift 2
  done
  local -a g; set -f; g=($globs); set +f
  register_check "$id" "$sev" none "$lits" "$desc" "$re" "${g[@]}"
}

register_check() {
  local id=$1 sev=$2 dec=$3 pre=$4 desc=$5 re=$6; shift 6
  CHECK_IDS+=("$id"); CHECK_TYPE[$id]=content
  CHECK_SEV[$id]=$sev; CHECK_DEC[$id]=$dec; CHECK_PRE[$id]=$pre
  CHECK_DESC[$id]=$desc; CHECK_RE[$id]=$re
  CHECK_INC[$id]="${*:-${DEFAULT_INCLUDES[*]}}"
}

register_file_check() {
  local id=$1 sev=$2 desc=$3 glob=$4; shift 4
  CHECK_IDS+=("$id"); CHECK_TYPE[$id]=file
  CHECK_SEV[$id]=$sev; CHECK_DEC[$id]=none; CHECK_PRE[$id]=-
  CHECK_DESC[$id]=$desc; CHECK_RE[$id]=$glob; CHECK_INC[$id]=${glob//|/ }
  CHECK_EXCL[$id]="$*"
}

allow() { ALLOW_RE+=("$1"); ALLOW_CHECKS+=("$2"); ALLOW_WHY+=("$3"); }

is_allowed() {  # $1 file, $2 check id; sets ALLOW_MATCH to the rule's reason
  (( USE_ALLOW )) || return 1
  local i
  for i in "${!ALLOW_RE[@]}"; do
    [[ $1 =~ ${ALLOW_RE[$i]} ]] || continue
    if [[ ${ALLOW_CHECKS[$i]} == all || ",${ALLOW_CHECKS[$i]}," == *",$2,"* ]]; then
      ALLOW_MATCH=${ALLOW_WHY[$i]}; return 0
    fi
  done
  return 1
}

note_supp() {  # $1 id $2 file — count allowlisted files once per check
  [[ -n ${SUPP_SEEN[$1|$2]} ]] && return
  SUPP_SEEN[$1|$2]=1
  SUPP_COUNT[$1]=$(( SUPP_COUNT[$1] + 1 ))
  SUPP_FILES[$2]+=" $1"; SUPP_WHY[$2]=$ALLOW_MATCH
}

pre_args() {  # newline list -> PRE_ARGS=(-e lit -e lit ...)
  local l IFS=$'\n'; PRE_ARGS=()
  set -f; for l in $1; do [[ -n $l ]] && PRE_ARGS+=(-e "$l"); done; set +f
}

match_globs() {  # $1 path, rest: globs (matched against the basename)
  local f=${1##*/} g; shift
  for g; do [[ $f == $g ]] && return 0; done
  return 1
}

build_prune() {  # PRUNE=( -type d ( -name x -o -name y ) -prune -o )
  local d; local -a names=("${EXCLUDE_DIRS[@]}") n=()
  (( SKIP_CORE )) && names+=("${CORE_DIRS[@]}")
  for d in "${names[@]}"; do n+=(${n:+-o} -name "$d"); done
  PRUNE=(); (( ${#n[@]} )) && PRUNE=(-type d \( "${n[@]}" \) -prune -o)
}

setup_width() {
  local c=""
  if [[ -t 1 ]]; then
    c=$(tput cols 2>/dev/null) || c=""
    [[ $c =~ ^[0-9]+$ ]] || { c=$(stty size 2>/dev/null </dev/tty); c=${c#* }; }
  fi
  [[ $c =~ ^[0-9]+$ ]] && (( c >= 60 )) && WIDTH=$c
}

setup_colors() {
  setup_width
  if [[ -t 1 && $NO_COLOR != 1 ]]; then
    RED=$'\e[1;31m'; YEL=$'\e[1;33m'; GRN=$'\e[1;32m'; CYN=$'\e[36m'
    MAG=$'\e[35m'; DIM=$'\e[2m'; BLD=$'\e[1m'; RST=$'\e[0m'
  else
    RED=; YEL=; GRN=; CYN=; MAG=; DIM=; BLD=; RST=; NO_COLOR=1
  fi
}

# Running indicator on stderr: an updating status line on a terminal,
# dots otherwise (e.g. ssh 'bash -s' without a tty). Never in the report.
progress() {
  if [[ -t 2 ]]; then
    printf '\r\e[2K%s  scanning [%d/%d] %s  %ds%s' "$DIM" "$STEP" "$STEPS" "$1" "$SECONDS" "$RST" >&2
  elif (( ! NO_DOTS )); then
    (( PROGRESS_DOTS )) || printf 'scanning' >&2
    PROGRESS_DOTS=1; printf '.' >&2
  fi
}
clear_line() { [[ -t 2 ]] && printf '\r\e[2K' >&2; }
progress_done() {
  clear_line
  (( PROGRESS_DOTS )) && printf ' done (%ds)\n' "$SECONDS" >&2
  PROGRESS_DOTS=0
}

sev_label() {  # accepts name or rank
  case $1 in
    high|3)   printf '%s[HIGH]%s' "$RED" "$RST" ;;
    medium|2) printf '%s[MED] %s' "$YEL" "$RST" ;;
    *)        printf '%s[LOW] %s' "$CYN" "$RST" ;;
  esac
}

highlight() {  # $1 snippet, $2 regex
  if [[ $NO_COLOR == 1 ]]; then printf '%s\n' "$1"; return; fi
  printf '%s\n' "$1" | GREP_COLORS='mt=01;31' grep --color=always -E -- "$2" \
    || printf '%s\n' "$1"
}

add_domains() {  # $1 decoded string, $2 file
  local dom
  printf '%s\n' "$1" | perl -ne '
      print "$1\n" while m{(?:https?:)?//([a-z0-9.-]+\.[a-z]{2,})}gi;
      print "$1\n" if m{^([a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,})(?:/|$)}i;' |
  while IFS= read -r dom; do
    [[ -n $dom ]] || continue
    dom=${dom,,}
    [[ ${DOMAINS[$dom]} == *"$2 "* ]] || DOMAINS[$dom]+="$2 "
  done
}

# One tree walk: every file matching any selected content check's globs
# that contains any of their prefilter literals.
gather_candidates() {
  local id g d all_files=0
  local -a args eargs globs
  for id in "${CHECK_IDS[@]}"; do
    [[ ${#SELECTED[@]} -eq 0 || -n ${SELECTED[$id]} ]] || continue
    [[ ${CHECK_TYPE[$id]} == file ]] && continue
    set -f; globs+=(${CHECK_INC[$id]}); set +f
    if [[ ${CHECK_PRE[$id]} == - ]]; then all_files=1; continue; fi
    pre_args "${CHECK_PRE[$id]}"; eargs+=("${PRE_ARGS[@]}")
  done
  (( ${#globs[@]} )) || return 0
  printf '%s\n' "${globs[@]}" | sort -u | while IFS= read -r g; do args+=(--include="$g"); done
  for d in "${EXCLUDE_DIRS[@]}"; do args+=(--exclude-dir="$d"); done
  if (( SKIP_CORE )); then for d in "${CORE_DIRS[@]}"; do args+=(--exclude-dir="$d"); done; fi
  (( all_files )) && eargs=(-e '')

  progress "indexing files"
  # via a file, not a pipe: mapfile reads a pipe one byte per syscall (slow)
  grep -rlIF "${args[@]}" "${eargs[@]}" . 2>>"$ERRF" > "$TMPD/list"
  mapfile -t CANDIDATES < "$TMPD/list"
  CANDIDATES=("${CANDIDATES[@]#./}")
}

# Store one (check, file) result. Line/note/decoded are optional.
record_hit() {  # $1 id $2 file $3 rank $4 line $5 note $6 decoded(\n-list)
  local id=$1 f=$2 r=$3 ln=$4 note=$5 dec=$6 k="$1|$2" x
  if [[ -z ${CF_SEV[$k]} ]]; then
    CF_SEV[$k]=0; CF_FILES[$id]+="$f"$'\n'; HIT_COUNT[$id]=$(( HIT_COUNT[$id] + 1 ))
  fi
  (( r > CF_SEV[$k] )) && CF_SEV[$k]=$r
  (( r > ${CHECK_MAX[$id]:-0} )) && CHECK_MAX[$id]=$r
  (( r > ${FILE_SEV[$f]:-0} )) && FILE_SEV[$f]=$r
  [[ ${FILE_CHECKS[$f]} == *" $id "* ]] || FILE_CHECKS[$f]+=" $id "
  [[ -n $ln && ${CF_LINES[$k]} != *" $ln "* ]] && CF_LINES[$k]+=" $ln "
  if [[ -n $HIT_MAT && -z ${CF_MAT[$k]} ]]; then
    CF_PRE[$k]=$HIT_PRE; CF_MAT[$k]=$HIT_MAT; CF_POST[$k]=$HIT_POST; CF_SLN[$k]=$ln
  fi
  HIT_PRE=""; HIT_MAT=""; HIT_POST=""
  [[ -n $note ]] && CF_NOTE[$k]=$note
  if [[ -n $dec ]]; then
    printf '%s' "$dec" | while IFS= read -r x; do
      [[ $'\n'${CF_DEC[$k]} == *$'\n'"$x"$'\n'* ]] || CF_DEC[$k]+="$x"$'\n'
      [[ $'\n'${FILE_DEC[$f]} == *$'\n'"$x"$'\n'* ]] || FILE_DEC[$f]+="$x"$'\n'
    done
  fi
}

fmt_snip() {  # $1 pre $2 match $3 post $4 width -> dim code, matched part bold
  local pre=$1 mat=$2 post=$3 w=$(( ${4:-100} - 6 )) lead="" tail="" pl ql
  (( ${#mat} > w * 6 / 10 )) && mat="${mat:0:w*6/10-15}...${mat: -12}"
  pl=$(( (w - ${#mat}) / 3 )); (( pl < 0 )) && pl=0
  (( ${#pre} < pl )) && pl=${#pre}
  ql=$(( w - ${#mat} - pl )); (( ql < 0 )) && ql=0
  (( ${#pre} > pl )) && { pre=${pre: -pl}; lead="..."; }
  (( ${#post} > ql )) && { post=${post:0:ql}; tail="..."; }
  (( pl == 0 )) && pre=""
  printf '%s%s%s%s%s%s%s%s%s' "$DIM" "$lead$pre" "$RST" "$BLD" "$mat" "$RST" "$DIM" "$post$tail" "$RST"
}

print_finding() {  # -v only: rank file line check pre match post decoded
  local x
  clear_line
  printf '\n%s %s%s%s:%s  %s%s%s\n' "$(sev_label "$1")" "$MAG" "$2" "$RST" "$3" "$DIM" "$4" "$RST"
  printf '       %s\n' "$(fmt_snip "$5" "$6" "$7" $(( WIDTH - 8 )))"
  [[ -n $8 ]] && printf '%s' "$8" | while IFS= read -r x; do
    printf '       %s-> %s%s\n' "$RED" "$x" "$RST"
  done
}

run_check() {
  local id=$1 core=${CHECK_RE[$id]} dec=${CHECK_DEC[$id]} sev=${CHECK_SEV[$id]}
  local rank=${SEV_RANK[$sev]} f
  local -a incs files hits
  HIT_COUNT[$id]=0; SUPP_COUNT[$id]=0
  if [[ ${CHECK_TYPE[$id]} == file ]]; then run_file_check "$id"; return; fi

  set -f; incs=(${CHECK_INC[$id]}); set +f
  for f in "${CANDIDATES[@]}"; do match_globs "$f" "${incs[@]}" && files+=("$f"); done
  if [[ ${CHECK_PRE[$id]} != - && ${#files[@]} -gt 0 ]]; then
    pre_args "${CHECK_PRE[$id]}"
    printf '%s\0' "${files[@]}" | xargs -0 -r grep -lIF "${PRE_ARGS[@]}" -- 2>>"$ERRF" > "$TMPD/list"
    mapfile -t files < "$TMPD/list"
  fi
  progress "$id (${#files[@]} file(s))"
  (( ${#files[@]} )) || return 0

  # Perl finds matches and slices context by position (fast on huge minified
  # lines). Output: file US line US snippet US decode-window
  printf '%s\0' "${files[@]}" \
    | RE="$core" B=$CTX_BEFORE A=$CTX_AFTER W=$DECODE_WINDOW MAXB=$(( MAX_FILE_MB * 1048576 )) \
      MAXMB=$MAX_FILE_MB xargs -0 -r perl -ne '
        BEGIN { $re = qr/$ENV{RE}/; ($b, $a, $w) = @ENV{qw(B A W)};
                @ARGV = grep { (-s $_ // 0) <= $ENV{MAXB} or
                  (print STDERR "skipped, larger than $ENV{MAXMB} MB: $_\n") && 0 } @ARGV; }
        my $n = 0;
        while (/$re/g) {
          my ($s, $e) = ($-[0], $+[0]);
          my $pre = substr($_, ($s > $b ? $s - $b : 0), ($s > $b ? $b : $s));
          my $mat = substr($_, $s, $e - $s);
          my $post = substr($_, $e, $a);
          my $wi = substr($_, ($s > 120 ? $s - 120 : 0), ($s > 120 ? 120 : $s) + $e - $s + $w);
          # never print raw control chars (a file could carry terminal escapes)
          $post =~ s/[\r\n]+$//;
          for ($pre, $mat, $post) { s/[\r\n]+/ /g; s/[\x00-\x08\x0b-\x1f\x7f]/?/g; }
          $wi =~ s/[\r\n]+//g; $wi =~ tr/\x1f/ /;
          print "$ARGV\x1f$.\x1f$pre\x1f$mat\x1f$post\x1f$wi\n";
          last if ++$n >= 20;                       # cap matches per line
        }
        close ARGV if eof;                          # reset $. per file
      ' 2>>"$ERRF" > "$TMPD/list"
  mapfile -t hits < "$TMPD/list"

  local US=$'\x1f' hit file rest ln pre mat post key window x decoded rated hrank i=0
  local -A auto_skip kept_f rate_ok RATED
  # all matches rated by ONE rater process (see MATCH RATERS): "N<TAB>sev<TAB>note"
  if declare -F "rate_$id" >/dev/null; then
    printf '%s\n' "${hits[@]}" \
      | perl -ne 'chomp; my ($f, $l, $p, $m, $q) = split /\x1f/; print "$p\x1f$m\x1f$q\x1f$f\x1f$l\n"' \
      | "rate_$id" > "$TMPD/rated" 2>>"$ERRF"
    while IFS= read -r x; do
      if [[ $x =~ ^[0-9]+$'\t' ]]; then RATED[${x%%$'\t'*}]=${x#*$'\t'}
      else printf 'rate_%s: bad output line: %s\n' "$id" "${x:0:200}" >> "$ERRF"; fi
    done < "$TMPD/rated"
  fi
  for hit in "${hits[@]}"; do
    i=$(( i + 1 ))
    file=${hit%%"$US"*}; rest=${hit#*"$US"}
    ln=${rest%%"$US"*};  rest=${rest#*"$US"}
    pre=${rest%%"$US"*};  rest=${rest#*"$US"}
    mat=${rest%%"$US"*};  rest=${rest#*"$US"}
    post=${rest%%"$US"*}; window=${rest#*"$US"}

    if is_allowed "$file" "$id"; then note_supp "$id" "$file"; continue; fi
    hrank=$rank
    rated=${RATED[$i]}                           # per-match severity (see MATCH RATERS)
    if [[ ${rated%%$'\t'*} == skip ]]; then auto_skip[$file]=${rated#*$'\t'}; continue; fi
    if [[ ${rated%%$'\t'*} == ok ]]; then rate_ok[$file]=1; continue; fi
    [[ -n $rated ]] && hrank=${SEV_RANK[${rated%%$'\t'*}]:-$rank}
    kept_f[$file]=1
    key="$file:$ln"
    [[ ${REC_SEEN[$key]} == *" $id "* ]] && continue    # same check, same line
    REC_SEEN[$key]+=" $id "

    decoded=""
    # no decoder: show the rater's reason instead (e.g. what CLOAKING found)
    if [[ $dec == none && -n $rated ]]; then
      decoded="reason: ${rated#*$'\t'}"$'\n'
      [[ $rated == *' -> '* ]] && add_domains "//${rated##* -> }" "$file"   # target host
    fi
    if [[ $dec != none && -z ${DECODED_SEEN[$key:$dec]} ]]; then
      DECODED_SEEN[$key:$dec]=1
      printf '%s\n' "$window" | "decode_$dec" | while IFS= read -r x; do
        [[ -n $x ]] || continue
        x=${x:0:200}; decoded+="$x"$'\n'; add_domains "$x" "$file"
      done
    fi
    HIT_PRE=$pre; HIT_MAT=$mat; HIT_POST=$post
    record_hit "$id" "$file" "$hrank" "$ln" "" "$decoded"
    (( VERBOSE )) && print_finding "$hrank" "$file" "$ln" "$id" "$pre" "$mat" "$post" "$decoded"
  done
  # a file is ignored only if EVERY match in it was rated skip (or ok);
  # clean = every match rated ok: not listed or counted (--verify knows)
  for file in "${!auto_skip[@]}"; do
    [[ -n ${kept_f[$file]} ]] && continue
    ALLOW_MATCH="auto: ${auto_skip[$file]}"; note_supp "$id" "$file"
  done
  for file in "${!rate_ok[@]}"; do
    [[ -n ${kept_f[$file]}${auto_skip[$file]} ]] || FC_CLEAN[$id|$file]=1
  done
}

file_check_args() {  # $1 id -> FC_INC / FC_EXC find expressions
  local g
  FC_INC=(); FC_EXC=()
  set -f
  for g in ${CHECK_INC[$1]}; do
    if [[ $g == */* ]]; then FC_INC+=(${FC_INC:+-o} -ipath "$g")
    else FC_INC+=(${FC_INC:+-o} -iname "$g"); fi
  done
  for g in ${CHECK_EXCL[$1]}; do FC_EXC+=(${FC_EXC:+-o} -iname "$g"); done
  set +f
  (( ${#FC_EXC[@]} )) && FC_EXC=(! \( "${FC_EXC[@]}" \))
}

run_file_check() {
  local id=$1 rank=${SEV_RANK[${CHECK_SEV[$1]}]} f sv note
  local -a hits
  build_prune; file_check_args "$id"
  progress "$id"
  find . "${PRUNE[@]}" -type f \( "${FC_INC[@]}" \) "${FC_EXC[@]}" -print 2>>"$ERRF" > "$TMPD/list"
  mapfile -t hits < "$TMPD/list"
  hits=("${hits[@]#./}")

  if declare -F "classify_$id" >/dev/null; then
    # classify first: broad checks (every image / every .php) drop most files
    # as "ok", so the allowlist is only consulted for the rest
    # ("ok" lines go to a file, read back only by --verify: a bash read loop
    # over 40k lines costs seconds)
    (( ${#hits[@]} )) || return 0
    printf '%s\n' "${hits[@]}" | "classify_$id" > "$TMPD/classified"
    grep '^ok'$'\t' "$TMPD/classified" | cut -f3- > "$TMPD/clean.$id"
    grep -v '^ok'$'\t' "$TMPD/classified" | while IFS=$'\t' read -r sv note f; do
      if is_allowed "$f" "$id"; then note_supp "$id" "$f"; continue; fi
      if [[ $sv == skip ]]; then ALLOW_MATCH="auto: $note"; note_supp "$id" "$f"; continue; fi
      record_hit "$id" "$f" "${SEV_RANK[$sv]:-$rank}" "" "$note" ""
      (( VERBOSE )) && { clear_line; printf '\n%s %s%s%s  %s%s · %s%s\n' "$(sev_label "${SEV_RANK[$sv]:-$rank}")" \
        "$MAG" "$f" "$RST" "$DIM" "$note" "$id" "$RST"; }
    done
  else
    for f in "${hits[@]}"; do
      if is_allowed "$f" "$id"; then note_supp "$id" "$f"; continue; fi
      record_hit "$id" "$f" "$rank" "" "" ""
      (( VERBOSE )) && { clear_line; printf '\n%s %s%s%s  %s%s%s\n' "$(sev_label "$rank")" \
        "$MAG" "$f" "$RST" "$DIM" "$id" "$RST"; }
    done
  fi
}

# --verify: re-run every check the slow, independent way (plain recursive
# grep / full file listing; no prefilter, no perl) and diff the file lists.
verify_results() {
  local id d g f b ok bad=0 t="$TMPD/verify" missed extra
  local -a args incs expected got vinc vex
  progress_done; NO_DOTS=1   # status line only on a terminal from here on
  printf '\n%sVERIFY (brute-force scan vs fast scan)%s\n' "$BLD" "$RST"
  for id in "${CHECK_IDS[@]}"; do
    [[ ${#SELECTED[@]} -eq 0 || -n ${SELECTED[$id]} ]] || continue
    args=(); expected=(); got=()
    STEP=$(( STEP + 1 )); progress "verifying $id"
    if [[ ${CHECK_TYPE[$id]} == file ]]; then
      [[ -f $TMPD/clean.$id ]] && while IFS= read -r f; do FC_CLEAN[$id|$f]=1; done < "$TMPD/clean.$id"
      set -f; vinc=(${CHECK_INC[$id]}); vex=(${CHECK_EXCL[$id]}); set +f
      build_prune
      find . "${PRUNE[@]}" -type f -print 2>/dev/null | while IFS= read -r f; do
        f=${f#./}; b=${f##*/}; ok=0
        shopt -s nocasematch
        for g in "${vinc[@]}"; do
          if [[ $g == */* ]]; then [[ ./$f == $g ]] && ok=1
          else [[ $b == $g ]] && ok=1; fi
        done
        for g in "${vex[@]}"; do [[ $b == $g ]] && ok=0; done
        shopt -u nocasematch
        (( ok )) && ! is_allowed "$f" "$id" && [[ -z ${SUPP_SEEN[$id|$f]}${FC_CLEAN[$id|$f]} ]] && expected+=("$f")
      done
    else
      set -f; incs=(${CHECK_INC[$id]}); set +f
      for g in "${incs[@]}"; do args+=(--include="$g"); done
      for d in "${EXCLUDE_DIRS[@]}"; do args+=(--exclude-dir="$d"); done
      if (( SKIP_CORE )); then for d in "${CORE_DIRS[@]}"; do args+=(--exclude-dir="$d"); done; fi
      grep -rlIE "${args[@]}" -- "${CHECK_RE[$id]}" . 2>/dev/null | while IFS= read -r f; do
        f=${f#./}; is_allowed "$f" "$id" || [[ -n ${SUPP_SEEN[$id|$f]}${FC_CLEAN[$id|$f]} ]] || expected+=("$f")
      done
    fi
    printf '%s' "${CF_FILES[$id]}" | while IFS= read -r f; do [[ -n $f ]] && got+=("$f"); done
    printf '%s\n' "${expected[@]}" | grep . | sort -u > "$t.e"
    printf '%s\n' "${got[@]}" | grep . | sort -u > "$t.g"
    missed=$(comm -23 "$t.e" "$t.g"); extra=$(comm -13 "$t.e" "$t.g")
    rm -f -- "$t.e" "$t.g"
    clear_line
    if [[ -z $missed && -z $extra ]]; then
      printf '  %sOK%s    %-20s %d file(s) match\n' "$GRN" "$RST" "$id" "${#got[@]}"
    else
      bad=1
      printf '  %sDIFF%s  %-20s\n' "$RED" "$RST" "$id"
      [[ -n $missed ]] && printf '%s\n' "$missed" | sed 's/^/        missed by scan: /'
      [[ -n $extra  ]] && printf '%s\n' "$extra"  | sed 's/^/        only in scan:   /'
    fi
  done
  return $bad
}

# -----------------------------------------------------------------------------
#  SUMMARY
# -----------------------------------------------------------------------------
fmt_file() {  # path with the file name in bold; $2=1 also colours the extension
  local f=${1//[$'\x01'-$'\x1f'$'\x7f']/?} base dir name ext
  base=${f##*/}; dir=${f:0:${#f}-${#base}}
  if [[ ${2:-0} == 1 && ${base,,} != *.php && $base =~ ^(.+)(\.[pP][hH][pP].+)$ ]]; then
    name=${BASH_REMATCH[1]}; ext=${BASH_REMATCH[2]}
  elif [[ ${2:-0} == 1 && $base =~ ^(.+)(\.[^.]+)$ ]]; then
    name=${BASH_REMATCH[1]}; ext=${BASH_REMATCH[2]}
  else
    name=$base; ext=""
  fi
  printf '%s%s%s%s%s%s%s' "$dir" "$BLD" "$name" "$RST" "$BLD$YEL" "$ext" "$RST"
}

fmt_mtime() {  # dim date, plus a yellow "new" when modified recently
  local ep d
  ep=$(stat -c %Y -- "$1" 2>/dev/null) || return 0
  printf -v d '%(%d-%m-%Y %H:%M)T' "$ep"
  printf '%s%s%s' "$DIM" "$d" "$RST"
  (( NOW - ep < RECENT_DAYS * 86400 )) && printf ' %snew%s' "$YEL" "$RST"
}

print_section() {  # one block per check; files already listed are folded in
  local id=$1 f r k n=0 hidden=0 h=0 m=0 l=0 lines cnt x extra="" others top=0
  local -a new
  printf '%s' "${CF_FILES[$id]}" | while IFS= read -r f; do
    [[ -n $f && -z ${SHOWN[$f]} ]] || continue
    new+=("$f"); r=${CF_SEV[$id|$f]}
    (( r > top )) && top=$r
    case $r in 3) h=$((h+1));; 2) m=$((m+1));; *) l=$((l+1));; esac
  done
  (( ${#new[@]} )) || return 0          # everything already listed above
  (( (h>0) + (m>0) + (l>0) > 1 )) && extra=" · $h high, $m med, $l low"
  (( SUPP_COUNT[$id] )) && extra+=" · ${SUPP_COUNT[$id]} ignored"
  local desc=${CHECK_DESC[$id]} tailtxt=" · ${#new[@]} file(s)$extra" room
  room=$(( WIDTH - 10 - ${#id} - ${#tailtxt} ))
  (( ${#desc} > room )) && desc="${desc:0:room-3}..."
  printf '\n%s %s%s%s %s· %s%s%s\n' "$(sev_label "$top")" \
    "$BLD" "$id" "$RST" "$DIM" "$desc" "$tailtxt" "$RST"

  for f in "${new[@]}"; do printf '%s\t%s\n' "${CF_SEV[$id|$f]}" "$f"; done \
    | sort -t $'\t' -k1,1nr -k2,2 | while IFS=$'\t' read -r r f; do
    n=$(( n + 1 ))
    if (( n > LIST_LIMIT && ! VERBOSE )); then hidden=$(( hidden + 1 )); continue; fi
    k="$id|$f"; SHOWN[$f]=1
    lines=$(printf '%s\n' ${CF_LINES[$k]} | sort -n | head -n 5 | paste -sd, -)
    cnt=$(printf '%s\n' ${CF_LINES[$k]} | grep -c .)
    (( cnt > 5 )) && lines+=",+$(( cnt - 5 ))"

    # severity tag only when it differs from the section's
    if (( r != top )); then printf '  %s ' "$(sev_label "$r")"; else printf '  '; fi
    printf '%s' "$(fmt_file "$f" "$([[ ${CHECK_TYPE[$id]} == file ]] && echo 1 || echo 0)")"
    [[ -n $lines ]] && printf '%s:%s%s' "$DIM" "$lines" "$RST"
    printf '   %s' "$(fmt_mtime "$f")"
    if [[ -n ${CF_NOTE[$k]} ]]; then
      if (( r == 3 )); then printf '   %s%s%s' "$RED" "${CF_NOTE[$k]}" "$RST"
      else printf '   %s%s%s' "$DIM" "${CF_NOTE[$k]}" "$RST"; fi
    fi
    printf '\n'
    print_code_lines "$f" "$id"
  done
  (( hidden )) && printf '    %s...and %d more (use -v to list all)%s\n' "$DIM" "$hidden" "$RST"
}

# Under a file: the flagged code for this check, then any OTHER check on the
# same file - with its own code if it points at a different spot, or just
# its name if it matched code already shown (e.g. CHARCODE_ARITH inside the
# CHARCODE_SHIFT decoder).
print_code_lines() {  # $1 file $2 check: decoded value, flagged code, other parts
  local f=$1 id=$2 o k x w=$(( WIDTH - 16 )) shown=""
  printf '%s' "${FILE_DEC[$f]}" | while IFS= read -r x; do
    [[ -n $x ]] || continue
    (( ${#x} > w )) && x="${x:0:w-3}..."
    if [[ $x == "reason: "* ]]; then        # a rater's finding (no decoder)
      printf '      %sreason%s   %s\n' "$DIM" "$RST" "${x#reason: }"
    elif [[ $x == http* || $x == //* ]]; then
      printf '      %sdecoded%s  %s%s%s\n' "$DIM" "$RST" "$RED" "$x" "$RST"
    else
      printf '      %sdecoded%s  %s\n' "$DIM" "$RST" "$x"
    fi
  done
  k="$id|$f"
  if [[ -n ${CF_MAT[$k]} ]]; then
    printf '      %scode%s     %s\n' "$DIM" "$RST" "$(fmt_snip "${CF_PRE[$k]}" "${CF_MAT[$k]}" "${CF_POST[$k]}" "$w")"
    shown="${CF_PRE[$k]}${CF_MAT[$k]}${CF_POST[$k]}"
  fi
  # other HIGH checks pointing at a DIFFERENT spot = another part of the same
  # injection (e.g. the decoder next to the encoded URL). Same spot = skipped.
  for o in "${SECTION_ORDER[@]}"; do
    [[ $o != "$id" && ${FILE_CHECKS[$f]} == *" $o "* ]] || continue
    k="$o|$f"
    [[ -n ${CF_MAT[$k]} ]] && (( ${CF_SEV[$k]:-0} == 3 )) || continue
    [[ $shown == *"${CF_MAT[$k]}"* ]] && continue
    printf '      %salso%s     %s\n' "$DIM" "$RST" "$(fmt_snip "${CF_PRE[$k]}" "${CF_MAT[$k]}" "${CF_POST[$k]}" "$w")"
    shown+="${CF_PRE[$k]}${CF_MAT[$k]}${CF_POST[$k]}"
  done
}

print_summary() {
  set -f
  local id f k r total_supp=0 fh=0 fm=0 fl=0
  local -a order clean
  printf '\n%s═══════════════════════  SUMMARY  ═══════════════════════%s\n' "$BLD" "$RST"

  local kind
  for r in 3 2 1; do                      # severity, then code before files
    for kind in content file; do
      for id in "${CHECK_IDS[@]}"; do
        [[ -n ${HIT_COUNT[$id]+x} && ${CHECK_TYPE[$id]} == "$kind" ]] || continue
        [[ $id == WATCHLIST ]] && continue            # shown in its own section
        (( HIT_COUNT[$id] )) && (( ${CHECK_MAX[$id]:-0} == r )) && order+=("$id")
      done
    done
  done
  for id in "${CHECK_IDS[@]}"; do
    [[ -n ${HIT_COUNT[$id]+x} ]] || continue
    (( total_supp += SUPP_COUNT[$id] ))
    [[ $id == WATCHLIST ]] && continue
    (( HIT_COUNT[$id] )) || clean+=("$id")
  done

  SECTION_ORDER=("${order[@]}")
  for id in "${order[@]}"; do print_section "$id"; done
  (( ${#clean[@]} )) && printf '\n  %sClean: %s%s\n' "$GRN" "$(printf '%s\n' "${clean[@]}" | paste -sd' ' -)" "$RST"

  if (( ${#WATCH[@]} )); then
    printf '\n%sWatchlist%s %s(domains you supplied - matches need confirming before reporting)%s\n' \
      "$BLD$CYN" "$RST" "$DIM" "$RST"
    printf '  %swatching: %s%s\n' "$DIM" "${WATCH[*]}" "$RST"
    if (( ${HIT_COUNT[WATCHLIST]:-0} )); then
      printf '%s' "${CF_FILES[WATCHLIST]}" | sort | while IFS= read -r f; do
        [[ -n $f ]] || continue
        k="WATCHLIST|$f"
        printf '  %s%s:%s%s   %s\n' "$(fmt_file "$f")" "$DIM" \
          "$(printf '%s\n' ${CF_LINES[$k]} | sort -n | head -n 5 | paste -sd, -)" "$RST" "$(fmt_mtime "$f")"
        [[ -n ${CF_MAT[$k]} ]] && printf '      %scode%s     %s\n' "$DIM" "$RST" \
          "$(fmt_snip "${CF_PRE[$k]}" "${CF_MAT[$k]}" "${CF_POST[$k]}" $(( WIDTH - 16 )))"
      done
    else
      printf '  %sno plain-text matches%s\n' "$GRN" "$RST"
    fi
  fi

  if (( ${#DOMAINS[@]} )); then
    printf '\n%sHidden domains%s %s(decoded from obfuscated code - suspicious until checked):%s\n' "$BLD" "$RST" "$DIM" "$RST"
    printf '%s\n' "${!DOMAINS[@]}" | sort | while IFS= read -r f; do
      printf '  %s%s%s  %s<- %s%s' "$RED" "$f" "$RST" "$DIM" "${DOMAINS[$f]% }" "$RST"
      on_watchlist "$f" && printf '  %s(on your watchlist)%s' "$CYN" "$RST"
      printf '\n'
    done
    printf '\n  %sCheck each with VirusTotal and GTMetrix (several test locations) to see what it serves.%s\n' "$DIM" "$RST"
  fi

  for f in "${!FILE_SEV[@]}"; do
    case ${FILE_SEV[$f]} in 3) fh=$((fh+1));; 2) fm=$((fm+1));; *) fl=$((fl+1));; esac
  done
  printf '\n  Affected files: %s%d high%s, %s%d medium%s, %d low  (%d total)\n' \
    "$RED" "$fh" "$RST" "$YEL" "$fm" "$RST" "$fl" "${#FILE_SEV[@]}"
  if (( total_supp )); then
    printf '  %sIgnored: %d file(s) matched a check but are known-legit (allowlist rules, or\n  auto-ignored like saved HTML pages) and were left out above. -v lists them with\n  the reason; --no-allowlist includes allowlisted ones.%s\n' \
      "$DIM" "${#SUPP_FILES[@]}" "$RST"
    if (( VERBOSE )); then
      printf '%s\n' "${!SUPP_FILES[@]}" | sort | while IFS= read -r f; do
        printf '    %s%s [%s] - %s%s\n' "$DIM" "$f" \
          "$(printf '%s\n' ${SUPP_FILES[$f]} | sort -u | paste -sd, -)" "${SUPP_WHY[$f]}" "$RST"
      done
    fi
  fi
  (( SKIP_CORE )) && printf '  %sSkipped WP core (%s) - run: wp core verify-checksums%s\n' \
    "$DIM" "${CORE_DIRS[*]}" "$RST"
  printf '  %sScanned %d candidate file(s) in %ds · "new" = modified in the last %d days%s\n' \
    "$DIM" "${#CANDIDATES[@]}" "$SECONDS" "$RECENT_DAYS" "$RST"
  printf '\n  %sFindings are indicators for review, not confirmed infections. Verify before reporting to the client.%s\n' \
    "$YEL" "$RST"

  if [[ -s $ERRF ]]; then
    printf '\n%s[!] %d file(s) could not be scanned (unreadable/too large) - results may be INCOMPLETE:%s\n' \
      "$RED" "$(wc -l < "$ERRF")" "$RST"
    head -n3 "$ERRF" | sed 's/^/    /'
    (( ${#FILE_SEV[@]} == 0 )) && return 2
  fi
  (( ${#FILE_SEV[@]} == 0 )) && printf '\n  %sNo indicators found. Externally flagged domains may still load via\n  encoding not covered here or from the DB; check with GTMetrix.%s\n' "$GRN" "$RST"
  return $(( ${#FILE_SEV[@]} > 0 ))
}

usage() {
  cat <<EOF
fixed-malscan.sh v$VERSION — scan for obfuscated JS/PHP injections and exposed files

Usage: fixed-malscan.sh [options] [DIR]        (DIR defaults to current dir)

  -c, --checks ID,ID   run only these checks
  -l, --list           list checks, allowlist rules and the watchlist, then exit
  -w, --watch D1,D2    also look for these domains in plain text (e.g. ones
                       confirmed malicious in earlier cleanups). Nothing is built
                       in: you decide the list per run. Matches are shown in a
                       separate "Watchlist" section, as leads to confirm.
      --watch-file F   same, from a file on the server (one domain per line, # comments)
  -v, --verbose        list every file, print each finding with its code
                       snippet, and list allowlisted files with the reason
      --verify         cross-check results against a brute-force scan (slower)
  -o, --report FILE    also save a plain-text report (must be outside DIR)
      --include-core   also scan wp-admin / wp-includes
      --no-allowlist   ignore the allowlist
  -k, --keep           do NOT self-delete the script
      --no-color       disable colours
  -h, --help           this help

Examples (from inside the site folder):
  curl --proto '=https' -fsSL <raw URL> | bash
  curl --proto '=https' -fsSL <raw URL> | bash -s -- -v
  curl --proto '=https' -fsSL <raw URL> | bash -s -- --watch userstatics.com,bad.example
  curl --proto '=https' -fsSL <raw URL> | bash -s -- /path/to/site --verify

Findings are indicators for review, not confirmed infections.

Exit codes: 0 = clean, 1 = findings, 2 = error
EOF
}

self_delete() {
  local self
  self=$(readlink -f -- "${BASH_SOURCE[0]}" 2>/dev/null) || return
  [[ $KEEP == 1 || -z $self || ! -f $self ]] && return
  grep -q 'FIXED-MALSCAN-SELF-DELETE-MARKER' -- "$self" 2>/dev/null || return
  rm -f -- "$self" \
    && printf '%s[i] Script removed from disk: %s (use --keep to retain)%s\n' "$DIM" "$self" "$RST" >&2 \
    || printf '%s[!] Could not delete %s — remove it manually!%s\n' "$RED" "$self" "$RST" >&2
}

scan_all() {
  local id sev rc n=0
  printf -v NOW '%(%s)T' -1
  printf '%sfixed-malscan v%s%s  target: %s%s%s  host: %s  %s\n' "$BLD" "$VERSION" "$RST" \
    "$CYN" "$TARGET" "$RST" "$(hostname -s 2>/dev/null || uname -n)" "$(date '+%d-%m-%Y %H:%M:%S')"
  local w; for w in "${WARNINGS[@]}"; do printf '%s[!] %s%s\n' "$YEL" "$w" "$RST"; done
  (( ${#WATCH[@]} )) && printf '%swatching for: %s%s\n' "$DIM" "${WATCH[*]}" "$RST"
  SECONDS=0
  for id in "${CHECK_IDS[@]}"; do
    [[ ${#SELECTED[@]} -eq 0 || -n ${SELECTED[$id]} ]] && n=$(( n + 1 ))
  done
  STEPS=$(( 1 + n * (VERIFY ? 2 : 1) )); STEP=1
  gather_candidates
  for sev in high medium low; do
    for id in "${CHECK_IDS[@]}"; do
      [[ ${CHECK_SEV[$id]} == "$sev" ]] || continue
      [[ ${#SELECTED[@]} -eq 0 || -n ${SELECTED[$id]} ]] || continue
      STEP=$(( STEP + 1 )); run_check "$id"
    done
  done
  (( VERIFY )) && verify_results
  progress_done
  print_summary; rc=$?; set +f
  return $rc
}

main() {
  trap cleanup EXIT
  trap on_signal INT TERM HUP

  local only="" list=0 wa
  local -a WATCH_ARGS=()
  while (( $# )); do
    case $1 in
      -c|--checks)    [[ -n ${2:-} ]] || die "$1 needs a value"; only=$2; shift ;;
      -l|--list)      list=1 ;;
      -v|--verbose)   VERBOSE=1 ;;
      -w|--watch)     [[ -n ${2:-} ]] || die "$1 needs a value"; WATCH_ARGS+=("w:$2"); shift ;;
      --watch-file)   [[ -n ${2:-} ]] || die "$1 needs a value"; WATCH_ARGS+=("f:$2"); shift ;;
      --verify)       VERIFY=1 ;;
      -o|--report)    [[ -n ${2:-} ]] || die "$1 needs a value"; REPORT=$2; shift ;;
      --include-core) SKIP_CORE=0 ;;
      --no-allowlist) USE_ALLOW=0 ;;
      -k|--keep)      KEEP=1 ;;
      --no-color)     NO_COLOR=1 ;;
      -h|--help)      setup_colors; self_delete; usage; return 0 ;;
      -*)             usage >&2; die "Unknown option: $1" ;;
      *)              TARGET=$1 ;;
    esac
    shift
  done

  setup_colors
  self_delete
  require_tools
  register_checks
  register_allowlist
  for wa in "${WATCH_ARGS[@]}"; do
    case $wa in w:*) add_watch "${wa#w:}";; f:*) add_watch_file "${wa#f:}";; esac
  done
  register_watchlist
  validate_checks

  if (( list )); then
    local id i
    for id in "${CHECK_IDS[@]}"; do
      printf '%s %-18s %s\n' "$(sev_label "${CHECK_SEV[$id]}")" "$id" "${CHECK_DESC[$id]}"
    done
    printf '\nAllowlist:\n'
    for i in "${!ALLOW_RE[@]}"; do
      printf '  %s\n      checks: %s — %s\n' "${ALLOW_RE[$i]}" "${ALLOW_CHECKS[$i]}" "${ALLOW_WHY[$i]}"
    done
    printf '\nWatchlist: '
    if (( ${#WATCH[@]} )); then printf '%s\n' "${WATCH[*]}"
    else printf 'none (nothing built in - add with --watch dom1,dom2 or --watch-file FILE)\n'; fi
    return 0
  fi

  [[ -d $TARGET ]] || die "Not a directory: $TARGET"
  [[ -r $TARGET && -x $TARGET ]] || die "No permission to read: $TARGET"
  cd -- "$TARGET" 2>/dev/null || die "Cannot enter: $TARGET"
  TARGET=$(pwd)
  # be gentle on production servers: lowest CPU and idle IO priority
  renice -n 19 -p $$ >/dev/null 2>&1
  command -v ionice >/dev/null 2>&1 && ionice -c 3 -p $$ >/dev/null 2>&1

  if [[ -n $only ]]; then
    local -a sel; local i
    local IFS=,; set -f; sel=($only); set +f; unset IFS
    for i in "${sel[@]}"; do
      [[ -n ${CHECK_SEV[$i]} ]] || die "Unknown check: $i (see -l)"
      SELECTED[$i]=1
    done
    (( ${#WATCH[@]} )) && SELECTED[WATCHLIST]=1   # --watch always runs if given
  fi

  if [[ -n $REPORT ]]; then
    local rdir rc
    rdir=$(cd -- "$(dirname -- "$REPORT")" 2>/dev/null && pwd) \
      || die "Report dir does not exist: $(dirname -- "$REPORT")"
    REPORT="$rdir/$(basename -- "$REPORT")"
    if [[ $REPORT == "$TARGET"/* || $REPORT == */public_html/* ]]; then
      die "Refusing to write the report inside the scanned dir / public_html"
    fi
    scan_all | tee -- "$TMPD/report"; rc=${PIPESTATUS[0]}
    sed -E 's/\x1b\[[0-9;]*m//g' -- "$TMPD/report" > "$REPORT" || die "Cannot write report: $REPORT"
    printf '\n  Report saved: %s\n' "$REPORT"
    return $rc
  fi
  scan_all
}

main "$@"; exit $?
