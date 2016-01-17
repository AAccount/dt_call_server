--install contrib and then create extension IN THE DATABASE for pgcrypt
drop table if exists users;

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
