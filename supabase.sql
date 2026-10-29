-- SecureBox — выполните в SQL Editor проекта Supabase.
-- В базе хранится ТОЛЬКО зашифрованный JSON-сейф.
-- Права ограничены аккаунтом через RLS.

create table if not exists public.securebox_vaults (
  user_id uuid primary key references auth.users(id) on delete cascade,
  version bigint not null default 1 check (version >= 1),
  payload jsonb not null,
  updated_at timestamptz not null default now()
);

alter table public.securebox_vaults enable row level security;

-- Сначала отзываем слишком широкие привилегии стандартной схемы public.
revoke all on public.securebox_vaults from public, anon, authenticated;
grant select, insert, update on public.securebox_vaults to authenticated;

-- Повторный запуск без конфликтов имён политик.
drop policy if exists "securebox_read_own" on public.securebox_vaults;
drop policy if exists "securebox_insert_own" on public.securebox_vaults;
drop policy if exists "securebox_update_own" on public.securebox_vaults;

create policy "securebox_read_own"
  on public.securebox_vaults for select to authenticated
  using ((select auth.uid()) = user_id);

create policy "securebox_insert_own"
  on public.securebox_vaults for insert to authenticated
  with check ((select auth.uid()) = user_id);

create policy "securebox_update_own"
  on public.securebox_vaults for update to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

-- updated_at автоматически меняется на каждой записи.
create or replace function public.securebox_touch_updated_at()
returns trigger language plpgsql set search_path = '' as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

revoke all on function public.securebox_touch_updated_at() from public, anon, authenticated;

drop trigger if exists securebox_on_update on public.securebox_vaults;
create trigger securebox_on_update
before update on public.securebox_vaults
for each row execute function public.securebox_touch_updated_at();
