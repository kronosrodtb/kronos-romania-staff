create table if not exists public.kronos_owner (
  id integer primary key check (id = 1),
  username text not null unique,
  salt text not null,
  password_hash text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.kronos_state (
  id integer primary key check (id = 1),
  data jsonb not null default '{"events":{},"rules":{},"customEvents":[],"customRules":[]}'::jsonb,
  updated_at timestamptz not null default now()
);

insert into public.kronos_state (id, data)
values (1, '{"events":{},"rules":{},"customEvents":[],"customRules":[]}'::jsonb)
on conflict (id) do nothing;

alter table public.kronos_owner enable row level security;
alter table public.kronos_state enable row level security;
