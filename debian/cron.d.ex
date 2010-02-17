#
# Regular cron jobs for the hipl package
#
0 4	* * *	root	[ -x /usr/bin/hipl_maintenance ] && /usr/bin/hipl_maintenance
