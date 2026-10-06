/* fixed-malscan test sample - synthetic, harmless (example.com only) */
function a(t){return t.charCodeAt(0)-48}function b(c){return c.charCodeAt(0)-"A".charCodeAt(0)+10}function c(t,s){return t[s].charCodeAt(1)+1===t[s+1].charCodeAt(1)}function d(o){return 95===o.id.charCodeAt(o.id.lastIndexOf("/")+1)}function e(t,i){for(var n=t[i-1].charCodeAt(0)+1,r=t[i+1].charCodeAt(0)-1,a=n,d=[];a<=r;)d.push(String.fromCharCode(a)),a++;return d}
var s="x",o="";for(var i=0;i<s.length;i++){var c=s.charCodeAt(i)^7;o+=String.fromCharCode(c)}
