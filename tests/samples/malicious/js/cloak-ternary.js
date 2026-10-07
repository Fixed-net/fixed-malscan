/* fixed-malscan test sample - synthetic, harmless (example.com only) */
var go = /Mobi|Android/i.test(navigator.userAgent) ? window.open("https://tern.example.com/") : 0;
