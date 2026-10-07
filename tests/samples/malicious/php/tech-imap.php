<?php
// fixed-malscan test sample - synthetic, harmless (example.com only)
imap_open("{x.example.com:143/imap}INBOX -oProxyCommand=x", "", "");
