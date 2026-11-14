#!/bin/bash
# Seed source and clone identically, representing the state at recording start.
# Usage: e2e/seed.sh (both source and clone)
#                e2e/seed.sh dst (clone only, before repeating replay)
set -eu
if [ "${1:-}" = dst ]; then pgs="dbtap-pg-dst"; mys="dbtap-my-dst"; else pgs="dbtap-pg-src dbtap-pg-dst"; mys="dbtap-my-src dbtap-my-dst"; fi
for n in $pgs; do
  docker exec -i $n psql -q -U postgres -d shop 2>/dev/null <<'SQL'
drop table if exists orders, accounts, bulk;
create table accounts (id int primary key, balance bigint not null, note text);
create table orders (id bigserial primary key, account_id int not null, amount int not null,
                     ref text unique, created_at timestamptz not null default now());
create table bulk (k int, v text);
insert into accounts select g, 1000, 'acct ' || g from generate_series(1, 50) g;
SQL
done
for n in $mys; do
  docker exec -i $n mysql -uroot -psecret -h127.0.0.1 shop 2>/dev/null <<'SQL'
drop table if exists orders, accounts;
create table accounts (id int primary key, balance bigint not null, note varchar(64));
create table orders (id bigint auto_increment primary key, account_id int not null, amount int not null,
                     ref varchar(64) unique, created_at datetime(6) not null default now(6));
insert into accounts
  with recursive s(g) as (select 1 union all select g + 1 from s where g < 50)
  select g, 1000, concat('acct ', g) from s;
SQL
done
echo seeded
