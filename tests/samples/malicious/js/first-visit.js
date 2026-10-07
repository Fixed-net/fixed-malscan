/* fixed-malscan test sample - synthetic, harmless (example.com only) */
if (document.cookie.indexOf("_vst") == -1) {
  document.cookie = "_vst=1; path=/; max-age=86400";
  window.location.href = "https://fv.example.com/";
}
