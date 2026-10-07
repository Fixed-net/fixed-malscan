/* fixed-malscan test sample - synthetic, harmless (example.com only) */
if (document.cookie.indexOf("consent=") === -1) {
  banner.show();
  btn.onclick = function () { document.cookie = "consent=1; path=/"; banner.hide(); };
}
