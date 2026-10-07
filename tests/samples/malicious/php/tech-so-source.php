<?php
// fixed-malscan test sample - synthetic, harmless (example.com only)
$c = "void __attribute__((constructor)) i(){}";
$cmd = "gcc -fPIC -shared -o /tmp/x.so /tmp/x.c";
