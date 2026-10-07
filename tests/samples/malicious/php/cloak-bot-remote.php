<?php
// fixed-malscan test sample - synthetic, harmless (example.com only)
$ua = strtolower($_SERVER["HTTP_USER_AGENT"]);
if (strpos($ua, "bot") !== false || strpos($ua, "spider") !== false) {
    echo file_get_contents("https://doorway.example.com/page.html");
}
