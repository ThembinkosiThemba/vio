---
name: harden-ubuntu
description: Baseline hardening for a fresh Ubuntu or Debian VPS
applies_to: ubuntu, debian
---
1. Run check_run to see where the host stands. Read host_facts for the login user and SSH port.
2. Make sure the operator has a working key login for a non-root admin user before touching root login.
   If the login user is root, propose user_add (admin) + key_add with a key the operator gives you,
   and ask them to test logging in as that user before going further.
3. SSH: one sshd_set with PasswordAuthentication no, KbdInteractiveAuthentication no,
   PermitEmptyPasswords no, X11Forwarding no, MaxAuthTries 4, and PermitRootLogin no
   (prohibit-password if vio itself logs in as root).
4. Firewall: if ufw is missing, pkg_install ufw. Then fw_allow the SSH port the operator is connected on,
   fw_allow each public service the operator confirms (80, 443, ...), then fw_enable.
   Never enable a firewall without the SSH port allowed earlier in the same plan.
5. Updates: pkg_upgrade with security true, then autoupdates_enable.
6. If password logins must stay on for some reason, fail2ban_configure.
7. If /var/run/reboot-required exists afterwards, tell the operator; propose host_reboot only if they ask.
Group these into one or two plans so the operator approves a coherent change, not a dozen prompts.
