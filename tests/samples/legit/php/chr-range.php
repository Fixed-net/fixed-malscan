<?php
// fixed-malscan test sample - synthetic, harmless (example.com only)
$b = array_map('chr', range(0x80, 0xFF)); $r = implode('', array_map('chr', $bytes));
