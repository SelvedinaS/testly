TESTLY — OVO IDE NA RENDER
===========================

Uploaduj SAMO sadrzaj ovog foldera na Render/GitHub repo za backend.

Render postavke:
- Runtime: Node
- Build command: ostavi prazno
- Start command: node server.js

Environment variables obavezno:
- JWT_SECRET = duga nasumicna vrijednost
- ADMIN_USER = admin (ili drugo ime)
- ADMIN_PASSWORD = jaka lozinka
- ADSENSE_ENABLED = false

Kad Render zavrsi deploy, dobit ces URL npr:
https://testly-api.onrender.com

Taj URL zatim upisi u NETLIFY-FRONTEND/config.js.

VAZNO O PODACIMA:
Backend trenutno cuva korisnike/challenge rezultate u JSON fajlovima. Za pravi javni sajt je preporucen Render Persistent Disk (DATA_DIR=/var/data) ili baza poput MongoDB/PostgreSQL, da podaci ne nestanu pri novom deployu/restartu instance.

Provjera:
Otvori https://TVOJ-RENDER-URL/api/health
Treba pisati {"ok":true,...}
