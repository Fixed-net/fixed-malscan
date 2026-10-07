<?php
// fixed-malscan test sample - synthetic, harmless (example.com only)
putenv("LD_PRELOAD=/tmp/x.so"); mail("a@example.com", "", "");
