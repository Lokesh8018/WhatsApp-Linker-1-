-- WhatsApp Linker — Supabase Schema
-- Run this in the Supabase SQL Editor to set up required tables.

-- Stats table
create table if not exists stats (
  id bigint primary key default 1,
  messages_sent bigint default 0,
  messages_received bigint default 0,
  active_devices int default 0,
  uptime_seconds bigint default 0,
  updated_at timestamptz default now()
);

-- Logs table
create table if not exists logs (
  id uuid primary key default gen_random_uuid(),
  level text,
  message text,
  created_at timestamptz default now()
);

-- Message history table
create table if not exists message_history (
  id uuid primary key default gen_random_uuid(),
  direction text, -- 'sent' or 'received'
  phone text,
  message text,
  status text,
  created_at timestamptz default now()
);

-- Devices table
create table if not exists devices (
  id text primary key,
  name text,
  phone text,
  status text default 'disconnected',
  last_seen timestamptz,
  created_at timestamptz default now()
);

-- API Keys table
create table if not exists api_keys (
  id uuid primary key default gen_random_uuid(),
  name text,
  key text unique,
  created_at timestamptz default now(),
  last_used timestamptz
);

-- Bulk jobs table
create table if not exists bulk_jobs (
  id uuid primary key default gen_random_uuid(),
  status text default 'pending',
  total int default 0,
  progress int default 0,
  sent int default 0,
  failed int default 0,
  created_at timestamptz default now()
);

-- Scheduled messages table
create table if not exists scheduled_messages (
  id uuid primary key default gen_random_uuid(),
  phone text,
  message text,
  scheduled_at timestamptz,
  status text default 'pending',
  created_at timestamptz default now()
);

-- Row Level Security: only authenticated users can read/write
alter table stats enable row level security;
alter table logs enable row level security;
alter table message_history enable row level security;
alter table devices enable row level security;
alter table api_keys enable row level security;
alter table bulk_jobs enable row level security;
alter table scheduled_messages enable row level security;

create policy "Authenticated users only" on stats for all using (auth.role() = 'authenticated');
create policy "Authenticated users only" on logs for all using (auth.role() = 'authenticated');
create policy "Authenticated users only" on message_history for all using (auth.role() = 'authenticated');
create policy "Authenticated users only" on devices for all using (auth.role() = 'authenticated');
create policy "Authenticated users only" on api_keys for all using (auth.role() = 'authenticated');
create policy "Authenticated users only" on bulk_jobs for all using (auth.role() = 'authenticated');
create policy "Authenticated users only" on scheduled_messages for all using (auth.role() = 'authenticated');
