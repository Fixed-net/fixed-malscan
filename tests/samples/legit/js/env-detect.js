/* fixed-malscan test sample - synthetic, harmless (example.com only) */
var env=function(){var a=navigator.userAgent.toLowerCase();return{mobile:-1<a.indexOf("mobile"),iOS:/(ipad|iphone|ipod)/.test(a)}}();function load(u){var s=document.createElement("script");s.src="https://cdn.example.com/plugins/"+u;document.head.appendChild(s)}
