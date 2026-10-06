<?php
// fixed-malscan test sample - synthetic, harmless (example.com only)
$u = 'aHR0cHM6Ly9iNjR1cmwuZXhhbXBsZS5jb20vcGF5bG9hZC50eHQ=';
echo file_get_contents(base64_decode($u));
