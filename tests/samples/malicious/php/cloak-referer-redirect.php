<?php
// fixed-malscan test sample - synthetic, harmless (example.com only)
$ref = $_SERVER["HTTP_REFERER"];
if (preg_match("/google|bing|yahoo/i", $ref)) {
    header("Location: https://cloak.example.com/");
    exit;
}
