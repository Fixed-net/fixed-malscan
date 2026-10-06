/* fixed-malscan test sample - synthetic, harmless (example.com only) */
function rot13(s){return s.replace(/[a-z]/gi,function(c){return String.fromCharCode((c<="Z"?90:122)>=(c=c.charCodeAt(0)+13)?c:c-26)})}
