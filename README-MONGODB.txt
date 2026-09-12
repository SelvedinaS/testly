TESTLY + MONGODB ATLAS + ADMIN ANALYTICS

Ova verzija trajno čuva u MongoDB:
- registrovane korisnike
- anonimne visitor/session ID-jeve
- državu (približno, bez prikaza sirove IP adrese)
- izvor posjete (TikTok, Instagram, Google, Direct...)
- BS/EN jezik
- page views
- pokretanja i završavanja testova/igara
- rezultat svakog završenog testa
- popularnost sadržaja
- challengee i rezultate

Admin panel:
- live/online posjetioci (aktivni u zadnjih 5 minuta)
- registrovani vs gosti
- top države
- top izvori posjeta
- top igre/testovi
- posljednjih 250 završenih testova/igara
- svi posjetioci/sesije
- korisnički računi
- BS/EN prekidač

NAPOMENA:
Gost je anonimna browser sesija. Bez prijave nije moguće pouzdano znati stvarni identitet osobe.
Država se dobija samo približno iz IP geolokacije; sirova IP adresa se ne čuva u analytics dokumentu.

Render Environment Variables:
JWT_SECRET
ADMIN_USER
ADMIN_EMAIL
ADMIN_PASSWORD
ADSENSE_ENABLED=false
MONGODB_URI=<Atlas connection string>
MONGODB_DB=testly
