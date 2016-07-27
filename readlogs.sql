select
  to_timestamp(ts/1000) as tsreadable,
  ta.tagname as tag,
  message,
  t.typename as type,
  ip,
  who,
  relatedkey
from logs as l
join logtype as t on l.type = t.typeid
join tag as ta on l.tag = ta.tagid
order by ts desc;
 