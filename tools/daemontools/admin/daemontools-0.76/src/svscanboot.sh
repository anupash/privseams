
PATH=/command:/usr/local/bin:/usr/local/sbin:/bin:/sbin:/usr/bin:/usr/sbin:/usr/X11R6/bin

exec </dev/null
exec >/dev/null
exec 2>/dev/null

svc -dx SERVICE/* SERVICE/*/log

env - PATH=$PATH svscan SERVICE 2>&1 | \
env - PATH=$PATH readproctitle service errors: ................................................................................................................................................................................................................................................................................................................................................................................................................
