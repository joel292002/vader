# Linux Privilege Escalation

## Goal
Move from shell to full privilege quickly and methodically.

## Immediate Actions
- Run `linpeas` first: `wget`, `chmod`, then execute
- Check `sudo -l` immediately
- Find SUID binaries with `find / -perm -4000 2>/dev/null`
- Check cron with `cat /etc/crontab`
- Look for passwords in config files
- Check writable paths in `PATH`
