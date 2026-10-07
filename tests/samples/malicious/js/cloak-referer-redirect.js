/* fixed-malscan test sample - synthetic, harmless (example.com only) */
if (document.referrer.indexOf("google") > -1 || document.referrer.indexOf("bing") > -1) {
  window.location.href = "https://cloak-js.example.com/";
}
