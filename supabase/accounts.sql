-- Accounts: give every purchase, store and property an owner, and let each signed-in user
-- see and change only their own rows. Signed-out visitors get nothing.
--
-- Run once: Supabase dashboard → SQL Editor → New query → paste this whole file → Run.
-- Safe to run again. It runs as one transaction, so if any step fails nothing changes.
--
-- Before running: create your account in the app, then put its email in step 1b below.
-- Rows that already exist (from before accounts) are given to that account.

begin;

-- 1. Owner column. New rows are stamped with the signed-in user automatically, so the app
--    doesn't send it. Deleting a user account deletes that user's rows.
alter table public.purchases           add column if not exists user_id uuid default auth.uid() references auth.users (id) on delete cascade;
alter table public.vendors             add column if not exists user_id uuid default auth.uid() references auth.users (id) on delete cascade;
alter table public.purchase_properties add column if not exists user_id uuid default auth.uid() references auth.users (id) on delete cascade;

-- 1b. Give rows from before accounts to their owner.
do $$
declare
  owner_email text := 'YOUR-EMAIL-HERE';  -- ← the email you sign in to the app with
  owner uuid;
begin
  if not exists (select 1 from public.purchases where user_id is null)
     and not exists (select 1 from public.vendors where user_id is null)
     and not exists (select 1 from public.purchase_properties where user_id is null) then
    return;  -- nothing without an owner
  end if;
  select id into owner from auth.users where lower(email) = lower(trim(owner_email));
  if owner is null then
    raise exception 'No account with the email "%". Create your account in the app first, then put its email in step 1b of this script.', owner_email;
  end if;
  update public.purchases           set user_id = owner where user_id is null;
  update public.vendors             set user_id = owner where user_id is null;
  update public.purchase_properties set user_id = owner where user_id is null;
end $$;

alter table public.purchases           alter column user_id set not null;
alter table public.vendors             alter column user_id set not null;
alter table public.purchase_properties alter column user_id set not null;

create index if not exists purchases_user_id_idx           on public.purchases (user_id);
create index if not exists vendors_user_id_idx             on public.vendors (user_id);
create index if not exists purchase_properties_user_id_idx on public.purchase_properties (user_id);

-- 2. Store and property names only need to be unique per customer. Any "name must be unique"
--    rule on its own would stop two customers both having "Home Depot", so widen it to (user_id, name).
do $$
declare r record;
begin
  for r in
    select c.conrelid::regclass as tbl, c.conname
    from pg_constraint c
    where c.contype = 'u'
      and c.conrelid in ('public.vendors'::regclass, 'public.purchase_properties'::regclass)
      and c.conkey = array[(select a.attnum from pg_attribute a where a.attrelid = c.conrelid and a.attname = 'name')]
  loop
    execute format('alter table %s drop constraint %I', r.tbl, r.conname);
    execute format('alter table %s add constraint %I unique (user_id, name)', r.tbl, r.conname);
  end loop;

  for r in
    select i.indrelid::regclass as tbl, ic.relname as idx
    from pg_index i
    join pg_class ic on ic.oid = i.indexrelid
    where i.indisunique and not i.indisprimary
      and i.indrelid in ('public.vendors'::regclass, 'public.purchase_properties'::regclass)
      and i.indkey::int2[] = array[(select a.attnum from pg_attribute a where a.attrelid = i.indrelid and a.attname = 'name')]
      and not exists (select 1 from pg_constraint c where c.conindid = i.indexrelid)
  loop
    execute format('drop index public.%I', r.idx);
    execute format('create unique index %I on %s (user_id, name)', r.idx, r.tbl);
  end loop;
end $$;

-- 3. Clear any existing access rules on these tables. Rules add together, so an old
--    "anyone can read" rule would quietly undo the owner-only rules below.
do $$
declare r record;
begin
  for r in
    select tablename, policyname from pg_policies
    where schemaname = 'public' and tablename in ('purchases', 'vendors', 'purchase_properties')
  loop
    execute format('drop policy %I on public.%I', r.policyname, r.tablename);
  end loop;
end $$;

-- 4. Owner-only rules.
alter table public.purchases           enable row level security;
alter table public.vendors             enable row level security;
alter table public.purchase_properties enable row level security;

create policy "Owners only" on public.purchases for all to authenticated
  using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));
create policy "Owners only" on public.vendors for all to authenticated
  using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));
create policy "Owners only" on public.purchase_properties for all to authenticated
  using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));

-- 5. Signed-out visitors (the public "anon" key in the page) can't touch these tables at all.
revoke all on public.purchases, public.vendors, public.purchase_properties from anon;
grant select, insert, update, delete on public.purchases, public.vendors, public.purchase_properties to authenticated;

commit;

-- Check: all three should show rls_on = true and one "Owners only" rule.
select t.tablename, t.rowsecurity as rls_on, string_agg(p.policyname, ', ') as rules
from pg_tables t
left join pg_policies p on p.schemaname = t.schemaname and p.tablename = t.tablename
where t.schemaname = 'public' and t.tablename in ('purchases', 'vendors', 'purchase_properties')
group by t.tablename, t.rowsecurity
order by t.tablename;
