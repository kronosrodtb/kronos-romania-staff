# KRONOS ROMANIA — Site + Owner Panel

Proiect Node.js pentru site-ul Kronos România, cu:

- pagină publică Evenimente;
- pagină publică Model Sancțiuni;
- Owner Panel protejat cu login;
- un singur cont Owner;
- adăugare evenimente și sancțiuni;
- salvare și backup;
- API pentru sincronizarea conținutului public;
- PostgreSQL/Supabase în producție;
- fallback local JSON pentru testare locală.

## Rulare locală

Necesită Node.js 18+.

```bash
npm install
npm start
```

Apoi deschide `http://localhost:3000`.

Dacă `DATABASE_URL` nu este setat, aplicația folosește `data/store.json` local.

## Producție

Setează în hosting:

- `DATABASE_URL` = connection string PostgreSQL/Supabase
- `NODE_ENV=production`

La pornire, serverul creează automat tabelele necesare.

## Securitate

Parola Owner nu este pusă în HTML. Este derivată cu `scrypt` și stocată ca hash + salt. Sesiunea folosește un cookie HTTP-only.

## Fișiere principale

- `server.js` — serverul și API-ul
- `owner.html` — Owner Panel
- `evenimente.html` — site-ul public pentru evenimente
- `sanctiuni.html` — site-ul public pentru sancțiuni
- `index.html` — pagina principală
