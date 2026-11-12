---
name: disk-full
description: Find out what is filling a disk and how to free space safely
applies_to: any
---
1. disk_usage with no path: which filesystem is full, and is it space or inodes (run_command df -i)?
2. disk_usage on the mount point, then drill into the largest directory a level at a time.
3. Usual suspects: /var/log (rotated logs, a runaway app log), journald (journalctl --disk-usage),
   /var/lib/docker (images, build cache, container logs), /var/cache/apt, core dumps, old kernels,
   deleted-but-open files (run_command ls -l /proc/*/fd is noisy; prefer lsof if allowed, or ss/ps to find the writer).
4. Explain what is safe to delete and what is not. Application data (databases, uploads) is never "cleanup".
5. Prefer fixes that stop the growth (logrotate config via fs_write, an app log level) over one-off deletion.
   fs_remove only works under /tmp, /var/tmp, /var/log and /var/cache, and is backed up first.
