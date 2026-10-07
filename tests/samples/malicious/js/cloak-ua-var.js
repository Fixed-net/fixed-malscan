/* fixed-malscan test sample - synthetic, harmless (example.com only) */
var ua = navigator.userAgent.toLowerCase();
var x = 1;
if (/android|iphone/.test(ua)) { window.location = "https://ua-var.example.com/"; }
