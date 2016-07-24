select
  to_timestamp(ts/1000) as tsreadable,
  tag,
  message,
  type,
  ip,
  who,
  relatedkey
from logs
order by ts desc;
