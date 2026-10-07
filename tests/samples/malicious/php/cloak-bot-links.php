<?php
// fixed-malscan test sample - synthetic, harmless (example.com only)
if (stripos($_SERVER["HTTP_USER_AGENT"], "Googlebot") !== false) {
    echo '<a href="https://spam.example.com/">cheap pills</a>';
}
