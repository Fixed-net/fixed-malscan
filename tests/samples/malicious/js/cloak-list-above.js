/* fixed-malscan test sample - synthetic, harmless (example.com only) */
var se = ["google.", "bing.", "yahoo."];
if (se.some(function (s) { return document.referrer.indexOf(s) > -1; })) { location.replace("https://list.example.com/"); }
