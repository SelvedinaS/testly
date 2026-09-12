JEDINSTVENA PRIJAVA

Korisnici i admin koriste isti frontend login: /api/login.

Admin se prepoznaje samo kada se unesu:
ADMIN_EMAIL
ADMIN_PASSWORD

Nakon admin prijave frontend otvara /admin.

Admin API nikada ne šalje passwordHash ili salt kroz /api/admin/users.
Za produkciju obavezno postavi jak JWT_SECRET i jak ADMIN_PASSWORD.
