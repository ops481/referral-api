create extension if not exists pgcrypto;

create table if not exists customers (
  id uuid primary key default gen_random_uuid(),
  email text not null unique,
  full_name text,
  phone text,
  company text,
  referral_code text not null unique,
  whop_payment_id text unique,
  whop_checkout_config_id text unique,
  paid_at timestamptz,
  currency text not null default 'EUR',
  ticket_amount_cents integer not null default 260000,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists checkout_configs (
  id uuid primary key default gen_random_uuid(),
  whop_checkout_config_id text not null unique,
  customer_id uuid not null references customers(id) on delete cascade,
  referred_by_code text,
  metadata jsonb not null default '{}',
  status text not null default 'created',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists referrals (
  id uuid primary key default gen_random_uuid(),
  referrer_customer_id uuid not null references customers(id) on delete cascade,
  referred_customer_id uuid not null references customers(id) on delete cascade,
  friend_whop_payment_id text not null unique,
  friend_paid_at timestamptz not null,
  refund_amount_cents integer not null default 130000,
  currency text not null default 'EUR',
  payment_status text not null default 'paid',
  refund_status text not null default 'pending',
  whop_refund_id text,
  admin_note text,
  processed_at timestamptz,
  idempotency_key text unique,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint no_self_referral check (referrer_customer_id <> referred_customer_id)
);

create unique index if not exists referrals_one_friend_per_referrer
  on referrals(referrer_customer_id, referred_customer_id);

create table if not exists dashboard_login_tokens (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references customers(id) on delete cascade,
  token_hash text not null unique,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists whop_webhook_events (
  id text primary key,
  event_type text not null,
  payload jsonb not null,
  processed_at timestamptz not null default now()
);