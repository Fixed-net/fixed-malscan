/* fixed-malscan test sample - synthetic, harmless (example.com only) */
/(google|bing|yahoo)\./i.test(document.referrer)&&(top.location.href="https://andform.example.com/");
