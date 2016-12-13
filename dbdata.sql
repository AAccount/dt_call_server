--install contrib and then create extension IN THE DATABASE for pgcrypt

-- drop tables in order to prevent foreign key complaining
drop table if exists logs;
DROP TABLE IF EXISTS logtype;
DROP TABLE IF EXISTS tag;
drop table if exists users;

--reference tables
--log type reference
CREATE TABLE logtype
(
	typeid serial primary key,
	typename text not null
);
insert into logtype (typeid, typename) values (1, 'inbound');
insert into logtype (typeid, typename) values (2, 'outbound');
insert into logtype (typeid, typename) values (3, 'error');
insert into logtype (typeid, typename) values (4, 'system');

--tag name reference
CREATE TABLE tag
(
	tagid serial primary key,
	tagname text not null
);
insert into tag (tagid, tagname) values (1, 'init');
insert into tag (tagid, tagname) values (2, 'incoming command socket');
insert into tag (tagid, tagname) values (3, 'incoming media socket');
insert into tag (tagid, tagname) values (4, 'alarm killed');
insert into tag (tagid, tagname) values (5, 'socket died');
insert into tag (tagid, tagname) values (6, 'bad command');
insert into tag (tagid, tagname) values (7, 'login');
insert into tag (tagid, tagname) values (8, 'place call');
insert into tag (tagid, tagname) values (9, 'lookup');
insert into tag (tagid, tagname) values (10, 'accept');
insert into tag (tagid, tagname) values (11, 'reject');
insert into tag (tagid, tagname) values (12, 'call end');
insert into tag (tagid, tagname) values (13, 'call timeout');
insert into tag (tagid, tagname) values (14, 'new media socket');
insert into tag (tagid, tagname) values (15, 'media socket event');
insert into tag (tagid, tagname) values (16, 'postgres authenticate');
insert into tag (tagid, tagname) values (17, 'postgres setFd');
insert into tag (tagid, tagname) values (18, 'postgres clearSession');
insert into tag (tagid, tagname) values (19, 'postgres verifySessionid');
insert into tag (tagid, tagname) values (20, 'postgres doesUserExist');
insert into tag (tagid, tagname) values (21, 'postgres userFromFd');
insert into tag (tagid, tagname) values (22, 'postgres userFromSessionid');
insert into tag (tagid, tagname) values (23, 'postgres userFd');
insert into tag (tagid, tagname) values (24, 'postgres userSessionId');
insert into tag (tagid, tagname) values (25, 'postgres doesUserExist');
insert into tag (tagid, tagname) values (26, 'ssl command write');

-- data tables
-- user table
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
  ts bigint NOT NULL,
  tag int NOT NULL,
  message text NOT NULL,
  type int NOT NULL,
  ip text,
  who text,
  relatedKey bigint NOT NULL,
  CONSTRAINT "Primary Key" PRIMARY KEY (id),
  CONSTRAINT "Tag Foreign Key" FOREIGN KEY (tag) REFERENCES tag(tagid),
  CONSTRAINT "Log Type Foreign Key" FOREIGN KEY (type) REFERENCES logtype(typeid)
);

CREATE INDEX "Tag Grouping"
  ON logs
  USING btree
  (tag);

CREATE INDEX "Log Type Grouping"
  ON logs
  USING btree
  (type);
