---
name: tls-renew
description: Check TLS certificate expiry and why renewal is failing
applies_to: any
---
1. tls_cert on 443 with the site's name as servername: note notAfter and the issuer.
2. Find the ACME client: run_command certbot certificates, or Caddy (svc_status caddy) which renews by itself.
3. certbot: run_command systemctl list-timers to see certbot.timer; log_journal unit certbot;
   log_tail /var/log/letsencrypt/letsencrypt.log.
4. Common causes: port 80 blocked by the firewall (fw_status), DNS no longer pointing at this host,
   a web server config that hides /.well-known/acme-challenge, or rate limits.
5. Fixes are usually a firewall rule (fw_allow 80), a web server config edit (fs_patch with reload),
   or re-enabling the timer (svc_control enable certbot.timer).
