-- תפריט שבת: הגדרת מסד הנתונים ב-Supabase.
-- מדביקים את כל הקובץ ב-SQL Editor ולוחצים Run.
-- אפשר להריץ שוב: הקובץ מוחק קודם את מה שהוא יצר בהרצה קודמת. זה מוחק גם את כל הנתונים!

-- ---------- ניקוי מהרצה קודמת ----------
drop trigger if exists on_auth_user_created on auth.users;
drop table if exists public.dishes, public.events, public.templates, public.messages,
  public.members, public.persons, public.group_secrets, public.join_failures,
  public.groups, public.profiles cascade;
drop function if exists public.handle_new_user, public.is_member, public.is_group_creator,
  public.my_pid, public.check_code, public.create_group, public.join_lookup,
  public.join_group, public.claim_person, public.leave_group cascade;

-- ---------- טבלאות ----------

-- אין הרשמה עם מייל. כל דפדפן מקבל משתמש אנונימי (auth.users),
-- והוא מקושר לאדם (persons) בכל קבוצה שהצטרף אליה.
-- במכשיר חדש מקלידים את קוד הקבוצה ובוחרים את השם שלך, והאדם עובר למשתמש החדש.

create table public.groups (
  id text primary key,
  name text not null,
  color text,
  created_by text,  -- persons.id של מי שפתח את הקבוצה
  created_at bigint
);

-- קוד הצטרפות בן 4 ספרות.
create table public.group_secrets (
  gid text primary key references public.groups on delete cascade,
  code text not null check (code ~ '^[0-9]{4}$')
);

create table public.persons (
  id text primary key default gen_random_uuid()::text,
  gid text not null references public.groups on delete cascade,
  name text not null check (length(trim(name)) between 1 and 40),
  uid uuid references auth.users on delete set null,
  joined_at bigint
);
create unique index on public.persons (gid, uid);
create index on public.persons (uid);

-- ניסיונות הצטרפות עם קוד שגוי, כדי להגביל ניחושים.
create table public.join_failures (
  gid text not null references public.groups on delete cascade,
  at timestamptz not null default now()
);
create index on public.join_failures (gid, at);

create table public.messages (
  id text primary key default gen_random_uuid()::text,
  gid text not null references public.groups on delete cascade,
  pid text references public.persons on delete set null,
  text text not null,
  ts bigint not null
);
create index on public.messages (gid, ts desc);

create table public.templates (
  id text primary key default gen_random_uuid()::text,
  gid text not null references public.groups on delete cascade,
  name text not null,
  category text,
  kosher text,
  kind text,
  created_by text,
  created_at bigint
);
create index on public.templates (gid);

create table public.events (
  id text primary key,
  gid text not null references public.groups on delete cascade,
  title text not null,
  type text,
  date text not null,
  meals jsonb not null default '[]',
  created_by text,
  created_at bigint
);
create index on public.events (gid);

create table public.dishes (
  id text primary key default gen_random_uuid()::text,
  gid text not null references public.groups on delete cascade,
  eid text not null references public.events on delete cascade,
  kind text,
  name text not null,
  meal text,
  category text,
  kosher text,
  notes text,
  assignee text references public.persons on delete set null,
  status text not null default 'todo',
  shopping jsonb not null default '[]',
  created_by text,
  created_at bigint
);
create index on public.dishes (gid);
create index on public.dishes (assignee);

-- ---------- פונקציות עזר ----------

create function public.is_member(p_gid text) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.persons where gid = p_gid and uid = auth.uid());
$$;

-- האדם שלי בקבוצה.
create function public.my_pid(p_gid text) returns text
language sql stable security definer set search_path = '' as $$
  select id from public.persons where gid = p_gid and uid = auth.uid();
$$;

create function public.is_group_creator(p_gid text) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.groups g join public.persons p on p.id = g.created_by
                 where g.id = p_gid and p.uid = auth.uid());
$$;

-- בודקת את הקוד. אחרי 3 טעויות בשעה הקבוצה ננעלת להצטרפות עד שתעבור שעה,
-- כך שניחוש של קוד בן 4 ספרות לוקח חודשים.
create function public.check_code(p_gid text, p_code text) returns boolean
language plpgsql security definer set search_path = '' as $$
begin
  if auth.uid() is null then raise exception 'not signed in' using errcode = '42501'; end if;
  if (select count(*) from public.join_failures where gid = p_gid and at > now() - interval '1 hour') >= 3 then
    raise exception 'rate_limited';
  end if;
  if exists (select 1 from public.group_secrets where gid = p_gid and code = trim(p_code)) then
    return true;
  end if;
  if exists (select 1 from public.groups where id = p_gid) then
    insert into public.join_failures (gid) values (p_gid);
  end if;
  return false;
end;
$$;

-- פתיחת קבוצה: הקבוצה, הקוד ומי שפתח אותה נשמרים יחד.
create function public.create_group(p_id text, p_name text, p_color text, p_code text, p_person text) returns text
language plpgsql security definer set search_path = '' as $$
declare
  now_ms bigint := (extract(epoch from now()) * 1000)::bigint;
  pid text;
begin
  if auth.uid() is null then raise exception 'not signed in' using errcode = '42501'; end if;
  insert into public.groups (id, name, color, created_at) values (p_id, p_name, p_color, now_ms);
  insert into public.group_secrets (gid, code) values (p_id, trim(p_code));
  insert into public.persons (gid, name, uid, joined_at) values (p_id, trim(p_person), auth.uid(), now_ms)
    returning id into pid;
  update public.groups set created_by = pid where id = p_id;
  return pid;
end;
$$;

-- שלב ראשון בהצטרפות: עם הקוד הנכון מקבלים את רשימת השמות בקבוצה,
-- כדי שמי שכבר בקבוצה (למשל בטלפון חדש) יוכל לבחור את עצמו. קוד שגוי מחזיר null.
create function public.join_lookup(p_gid text, p_code text) returns jsonb
language plpgsql security definer set search_path = '' as $$
begin
  if not public.check_code(p_gid, p_code) then return null; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('id', id, 'name', name) order by joined_at)
                   from public.persons where gid = p_gid), '[]'::jsonb);
end;
$$;

-- מצטרפים כאדם חדש בקבוצה.
create function public.join_group(p_gid text, p_code text, p_name text) returns text
language plpgsql security definer set search_path = '' as $$
declare pid text;
begin
  if not public.check_code(p_gid, p_code) then return null; end if;
  pid := public.my_pid(p_gid);
  if pid is not null then
    update public.persons set name = trim(p_name) where id = pid;
    return pid;
  end if;
  insert into public.persons (gid, name, uid, joined_at)
    values (p_gid, trim(p_name), auth.uid(), (extract(epoch from now()) * 1000)::bigint)
    returning id into pid;
  return pid;
end;
$$;

-- "זה אני": האדם עובר למכשיר הזה. המכשיר הקודם מאבד את הגישה לקבוצה.
create function public.claim_person(p_gid text, p_code text, p_pid text) returns text
language plpgsql security definer set search_path = '' as $$
begin
  if not public.check_code(p_gid, p_code) then return null; end if;
  if not exists (select 1 from public.persons where id = p_pid and gid = p_gid) then return null; end if;
  update public.persons set uid = null where gid = p_gid and uid = auth.uid() and id <> p_pid;
  update public.persons set uid = auth.uid() where id = p_pid;
  return p_pid;
end;
$$;

-- יציאה מהקבוצה. אם יצא מי שפתח אותה, הוותיק הבא בקבוצה מקבל את ההרשאות שלו.
create function public.leave_group(p_gid text) returns void
language plpgsql security definer set search_path = '' as $$
declare pid text := public.my_pid(p_gid);
begin
  if pid is null then return; end if;
  delete from public.persons where id = pid;
  update public.groups set created_by =
    (select id from public.persons where gid = p_gid order by joined_at limit 1)
  where id = p_gid and created_by = pid;
end;
$$;

revoke execute on function public.is_member, public.my_pid, public.is_group_creator, public.check_code,
  public.create_group, public.join_lookup, public.join_group, public.claim_person, public.leave_group
  from public, anon;
grant execute on function public.is_member, public.my_pid, public.is_group_creator,
  public.create_group, public.join_lookup, public.join_group, public.claim_person, public.leave_group
  to authenticated;
revoke execute on function public.check_code from authenticated;

-- ---------- הרשאות ----------

alter table public.groups enable row level security;
alter table public.group_secrets enable row level security;
alter table public.persons enable row level security;
alter table public.join_failures enable row level security;
alter table public.messages enable row level security;
alter table public.templates enable row level security;
alter table public.events enable row level security;
alter table public.dishes enable row level security;

revoke all on all tables in schema public from anon, authenticated;
grant select, insert, update, delete on public.messages, public.templates, public.events, public.dishes to authenticated;
grant select, delete on public.groups, public.persons to authenticated;
grant select on public.group_secrets to authenticated;
-- אפשר לשנות רק את השדות האלה. השאר משתנים רק דרך הפונקציות למעלה.
grant update (name, color) on public.groups to authenticated;
grant update (code) on public.group_secrets to authenticated;
grant update (name) on public.persons to authenticated;

-- שמות הקבוצות גלויים לכל מי שנכנס לאתר, כדי שאפשר יהיה לבחור קבוצה להצטרף אליה.
create policy "groups read" on public.groups for select to authenticated using (true);
create policy "groups update by creator" on public.groups for update to authenticated
  using (public.is_group_creator(id));
create policy "groups delete by creator" on public.groups for delete to authenticated
  using (public.is_group_creator(id));

-- חברי הקבוצה רואים את הקוד (כדי לשלוח אותו לאחרים). רק מי שפתח את הקבוצה משנה אותו.
create policy "code read by members" on public.group_secrets for select to authenticated
  using (public.is_member(gid));
create policy "code update by creator" on public.group_secrets for update to authenticated
  using (public.is_group_creator(gid));

-- כל אחד משנה רק את השם של עצמו. מי שפתח את הקבוצה יכול להוציא ממנה אנשים.
create policy "persons read by members" on public.persons for select to authenticated
  using (public.is_member(gid));
create policy "persons update own" on public.persons for update to authenticated
  using (uid = auth.uid());
create policy "persons delete by creator" on public.persons for delete to authenticated
  using (public.is_group_creator(gid));

-- הצ'אט גלוי רק לחברי הקבוצה. כל אחד מוחק רק את ההודעות שלו.
create policy "messages read" on public.messages for select to authenticated
  using (public.is_member(gid));
create policy "messages insert" on public.messages for insert to authenticated
  with check (public.is_member(gid) and pid = public.my_pid(gid));
create policy "messages delete" on public.messages for delete to authenticated
  using (pid = public.my_pid(gid) or public.is_group_creator(gid));

-- תפריטים, מנות ומנות קבועות: גלויים ופתוחים לעריכה רק לחברי הקבוצה.
create policy "templates by members" on public.templates for all to authenticated
  using (public.is_member(gid)) with check (public.is_member(gid));
create policy "events by members" on public.events for all to authenticated
  using (public.is_member(gid)) with check (public.is_member(gid));
create policy "dishes read" on public.dishes for select to authenticated
  using (public.is_member(gid));
create policy "dishes insert" on public.dishes for insert to authenticated
  with check (public.is_member(gid) and exists (select 1 from public.events e where e.id = eid and e.gid = dishes.gid));
create policy "dishes update" on public.dishes for update to authenticated
  using (public.is_member(gid)) with check (public.is_member(gid));
create policy "dishes delete" on public.dishes for delete to authenticated
  using (public.is_member(gid));

-- ---------- עדכונים בזמן אמת ----------

alter publication supabase_realtime add table
  public.groups, public.group_secrets, public.persons, public.messages,
  public.templates, public.events, public.dishes;
