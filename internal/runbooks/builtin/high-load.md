---
name: high-load
description: Diagnose high CPU, memory pressure, or a slow server
applies_to: any
---
1. host_facts for CPU count and memory; run_command uptime for load averages; compare load to CPU count.
2. proc_list sorted by cpu, then by mem. Note the top processes and their parents.
3. Memory: run_command free -m and vmstat 1 5. Look for swap activity (si/so) and the OOM killer
   (log_journal with grep "Out of memory|oom-kill" since today).
4. I/O wait: high "wa" in vmstat or top -b -n 1 means disk-bound; check iostat if allowed and disk_usage.
5. Services: svc_list with failed true, and log_journal for the busy service.
6. Network: net_connections counts per remote address can reveal a flood or a scraper.
7. Answer with the cause and evidence first. Restarting a service (svc_control) treats the symptom;
   say so and suggest the real fix.
