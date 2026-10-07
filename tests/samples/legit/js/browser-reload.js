/* fixed-malscan test sample - synthetic, harmless (example.com only) */
/*
* In some browsers the reload keeps cached data, causing e.g. Google Maps to load anyway.
*/
function reload() {
  if (navigator.userAgent.toLowerCase().indexOf("firefox") > -1) {
    window.location.href = url.toString();
  }
}
