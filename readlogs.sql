select
  to_timestamp(ts) as ts,
  tag,
  message,
  type,
  ip,
  who,
  relatedkey
from logs