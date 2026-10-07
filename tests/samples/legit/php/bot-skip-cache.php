<?php
// fixed-malscan test sample - synthetic, harmless (example.com only)
if (preg_match("/bot|crawl|spider/i", $_SERVER["HTTP_USER_AGENT"])) {
    return false;
}
