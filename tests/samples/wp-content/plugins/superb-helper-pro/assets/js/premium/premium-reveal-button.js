/* fixed-malscan test sample - synthetic, harmless (example.com only) */
const d=e=>{try{e=decodeURIComponent(e);let t="";for(let r=0;r<e.length;r++)t+=String.fromCharCode(e.charCodeAt(r)-1);return atob(t)}catch(t){return e}};
