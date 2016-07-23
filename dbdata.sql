--install contrib and then create extension IN THE DATABASE for pgcrypt
drop table if exists users;
drop table if exists logs;

create table users
(
	username text primary key,
	saltedhash text not null,
	commandfd int,
	mediafd int,
	sessionid bigint
);

insert into users (username, saltedhash) values ('righthand', crypt('unlucky',gen_salt('bf')));
insert into users (username, saltedhash) values ('libprohibited', crypt('feedme',gen_salt('bf')));
insert into users (username, saltedhash) values ('zapper', crypt('railgun',gen_salt('bf')));

CREATE TABLE logs
(
  id serial,
  ts bigint NOT NULL DEFAULT 0,
  tag text NOT NULL,
  message text NOT NULL,
  type integer,
  ip text,
  who text,
  relatedKey bigint,
  CONSTRAINT "Primary Key" PRIMARY KEY (id)
);

CREATE INDEX "Tag Grouping"
  ON logs
  USING btree
  (tag COLLATE pg_catalog."default");

CREATE INDEX "Timestamp Sorter"
  ON logs
  USING btree
  (ts DESC NULLS LAST);
