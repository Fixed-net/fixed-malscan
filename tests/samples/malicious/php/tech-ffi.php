<?php
// fixed-malscan test sample - synthetic, harmless (example.com only)
$f = FFI::cdef("int system(const char *c);"); $f->system("id");
