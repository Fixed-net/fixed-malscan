<?php
// fixed-malscan test sample - synthetic, harmless (example.com only)
if (isset($_SERVER["HTTP_REFERER"])) {
  $r = $_SERVER["HTTP_REFERER"];
  $re = "#(google|yahoo|bing)#i";
  if (preg_match($re, $r)) { $c = curl_init($host . $path); }
}
