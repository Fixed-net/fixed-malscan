<?php
// fixed-malscan test sample - synthetic, harmless (example.com only)
function is_mob() { return preg_match("/Mobile|Android|iPhone/", $_SERVER["HTTP_USER_AGENT"]); }
if (is_mob()) { echo '<a href="/m/">mobile menu</a>'; }
