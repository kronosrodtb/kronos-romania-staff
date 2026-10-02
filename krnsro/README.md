# Kronos Romania Staff — Cloudflare Workers + Supabase

## Architecture
- Cloudflare Workers: API + static website
- Supabase PostgreSQL: owner account + persistent site data
- GitHub: source repository

## Required Cloudflare secrets
- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`
- `SESSION_SECRET`

Do NOT put the Supabase service-role key in HTML or browser JavaScript.

## Supabase
Run `schema.sql` once in Supabase SQL Editor.

## Deploy
Cloudflare can deploy the Worker from this repository. The Worker serves the files in `public/` and handles `/api/*`.
