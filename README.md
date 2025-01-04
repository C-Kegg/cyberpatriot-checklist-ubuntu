# Ubuntu cyber-patriot checklist

## **Forensic questions**

## Disable guest user

- In ___/etc/lightdm/lightdm.conf___ add the line ```allow-guest=false```
- Restart with ```sudo restart lightdm``` (will log you out)


## Check users

- In ___/etc/passwd___ check for users that
  - Have UID __0__ (root users)
  - Are not allowed in the README (comment them out)
- In ___/etc/group___ verify users are in the correct groups and that no groups have a GID of __0__
- Add any users specified in README with ```adduser [username]```


## Secure sudo

- Check /etc/sudoers to verify only users from group sudo can sudo (do so with visudo)
    - Verify only admins have access to ___/etc/sudoers___ and ___/etc/sudoers.d___
- Check ___/etc/group___ and remove non-admins from _sudo_ and _admin_ groups
- Verify with the command ```sudo -l -U [username]``` to see sudo permissions


## Check for unauthorized files/packages

- Use ```cd /home``` then ```ls -Ra *```  to find unauthorized files (can also use ``tree`` for this)
  - Can also use ```ls *.[filetype]``` to search by file types
- Check for unauthorized packages with ```apt list --installed```
- Check for unauthorized services with ```service --status-all``` (can also use _Synaptic_ or _BUM_ for managing services)
- _AisleRiot_ is almost always installed, so run ```apt autoremove --purge aisleriot```


## Change password requirements

- In ___/etc/login.defs___ add
```
     PASS_MIN_DAYS 7
     PASS_MAX_DAYS 90
     PASS_WARN_AGE 14
```

- Use ```apt-get install libpam-cracklib```
    - in ___/etc/pam.d/common-password___ add ``minlen=8`` and ``remember=5`` to the line with ___pam_unix.so___ in it
    - Add ``ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-`` to the line with _pam.cracklib.so_ in it
    - In ___/etc/pam.d/common-auth___ add ``deny=5 unlock_time=1800`` to the end of the line with _pam\_tally2.so_ in it to add an account lockout policy


## Change all passwords

- Use the command ```passwd [user]``` to change passwords to a secure password (in a competition environment, this should be the same for simplicity's sake)
  - Use ```passwd -a -S``` to verify all passwords are set up correctly
- Enable auto-updates + other small things
  - In the GUI go to settings and set everything to the best available option under the "Updates" tab
  - In Firefox/Chrome/browser, go to settings, read through, and set everything to the most secure option (auto-updates, pop-up blocker, block dangerous downloads, display warning on known malicious sites, etc.)
  - Start updates with "apt-get update" and "apt-get upgrade"
  - Set a message of the day in /etc/motd
  - Disable sharing the screen by going to settings -> sharing then turn it off
  - Use "apt-get autoremove --purge samba" to remove samba


## Secure ports

- Use the command ```ss -ln``` to check for open ports that are not on the loopback
  - For open ports that need to be closed
    - Use ```lsof -i :[port]``` or ```netstat -lntp``` then copy the program listening on the port with ```whereis [program]``` then copy where the program is with ```dpkg -S [location]``` then remove the associated package with ```apt-get purge [package]```
    - Verify the removal with ```ss -ln```


## Secure the network

- Enable the firewall with ```ufw enable```
  - Configure firewall (can also be done through Gufw)
    - Check for rules with ```ufw status numbered``` and delete any with ```ufw delete [number]```
    - Add new rules with ```ufw allow [port]```

- Enable syn cookie protection with ```sysctl -n net.ipv4.tcp_syncookies```
- Disable IPv6 with ```echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf``` (make sure it isn't needed in README)
- Disable IP forwarding with ```echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward```
- Prevent IP spoofing with ```echo "nospoof on" | sudo tee -a /etc/host.conf```
- Disable ICMP responses with ```echo “net.ipv4.icmp_echo_ignore_all = 1” >> /etc/sysctl.conf```
- Use "sysctl -p" then restart sysctl with "sysctl --system"


## Secure services

- Check config files for any services installed to secure them (PHP, SQL, WordPress, FTP, SSH, and Apache are common services that need to be secured)
  - For hosting services such as WordPress, FTP, or websites verify the files are not sensitive or prohibited
  - Google __"how to secure [service] ubuntu"__ (or, for geekier geeks than usual, ```wget https://www.google.com/search?q=how+to+secure+[service]+ubuntu```)
  - Verify all services are legitimate with "service --status-all" (can also use Synaptic or BUM)
  - Verify the services do not use any default credentials


## Check permissions for sensitive files

- Check the permissions of the following files with ```ls -al```
  - ___/etc/passwd___, ___/etc/group___, ___/etc/shadow___, ___/etc/sudoers___, and ___/var/www___
#### The permissions should be "-rw-r----- root: shadow"
- Use ```chmod -R 640 [path]``` to modify the permissions of the files, if necessary


## Check for malware

- Check ___/etc/rc.local___ to see if it contains anything other than ```exit 0``` (easiest thing to do is ```echo "exit 0" > /etc/rc.local```)
- Use ```ps -aux``` to list running services, check if __lkl__, __uberkey__, __THC-vlogger__, __PyKeylogger__, or __logkeys__ are running
- Install __rkhunter__ then update the properties with ```rkhunter --propupd``` then run with ```rkhunter --checkall```

- Secure SSH (if needed in README)
  - In /etc/ssh/sshd_config: 
    - Change the port from default
    - Set LoginGraceTime to 20
    - Set PermitRootLogin to no
    - Set StrictModes to yes
    - Set MaxAuthTries to 3
    - Set PermitEmptyPasswords to no
    - Change and uncomment protocol line to "Protocol 2"
    - Optional: For keyless authentication set PasswordAuthentication to no
  - Restart ssh with "service sshd restart"

- Install security packages (not sure if needed)

    - Auditd:
        - Install with ```apt-get install auditd```
        - Run it with ```auditctl -e 1```
    - Fail2ban:
        - Install with ```apt install fail2ban```
        - Verify its running with ```systemctl status fail2ban```
        - Configure with ```cp /etc/fail2ban/jail.{conf,local}```then edit ```/etc/fail2ban/jail.local```
        - Restart it with ```systemctl restart fail2ban```
    - SELinux: Be careful with it
        - Install with ```apt-get install selinux```
        - In ___/etc/selinux/config___ set the state of SELinux to _enforcing_