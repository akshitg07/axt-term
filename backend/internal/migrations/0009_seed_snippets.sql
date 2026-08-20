-- 0009: a starter snippet library.
--
-- These are the commands an engineer types on a fresh host anyway. Shipping them
-- means the snippet feature is useful on first login rather than an empty folder.
-- run_mode is 'insert' throughout: the command lands on the prompt for review.

INSERT INTO snippet_folders (id, parent_id, name, sort_order) VALUES
    ('snipf-linux',  NULL, 'Linux',      10),
    ('snipf-disk',   'snipf-linux', 'Disk',    10),
    ('snipf-memory', 'snipf-linux', 'Memory',  20),
    ('snipf-proc',   'snipf-linux', 'Processes', 30),
    ('snipf-net',    'snipf-linux', 'Network', 40),
    ('snipf-systemd', 'snipf-linux', 'systemd', 50),
    ('snipf-logs',   'snipf-linux', 'Logs',    60),
    ('snipf-docker', NULL, 'Docker',     20),
    ('snipf-kube',   NULL, 'Kubernetes', 30),
    ('snipf-nginx',  NULL, 'Nginx',      40);

INSERT INTO snippets (id, folder_id, name, description, body, shell, os_family, variables_json, run_mode, created_at, updated_at) VALUES
    ('snip-df', 'snipf-disk', 'Disk usage by filesystem',
     'Human-readable free space, real filesystems only',
     'df -hT -x tmpfs -x devtmpfs', 'sh', 'linux', '[]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-du-top', 'snipf-disk', 'Largest directories here',
     'Top 20 space consumers below the current directory',
     'du -xhd1 . 2>/dev/null | sort -rh | head -20', 'sh', 'linux', '[]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-inodes', 'snipf-disk', 'Inode usage',
     'The disk-full cause that df -h does not show',
     'df -ih -x tmpfs -x devtmpfs', 'sh', 'linux', '[]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-largest-files', 'snipf-disk', 'Largest files under a path',
     'Find the 20 biggest files below {path}',
     'find {path} -xdev -type f -printf ''%s\t%p\n'' 2>/dev/null | sort -rn | head -20 | awk ''{printf "%.1f MiB\t%s\n", $1/1048576, $2}''',
     'bash', 'linux',
     '[{"name":"path","label":"Search from","default":"/var","required":true}]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-free', 'snipf-memory', 'Memory and swap',
     'Totals including buffers and cache',
     'free -h', 'sh', 'linux', '[]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-top-mem', 'snipf-memory', 'Top memory consumers',
     'Processes sorted by resident set size',
     'ps -eo pid,user,rss,pmem,comm --sort=-rss | head -20', 'sh', 'linux', '[]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-oom', 'snipf-memory', 'Recent OOM kills',
     'What the kernel killed and when',
     'journalctl -k --no-pager | grep -iE ''killed process|out of memory'' | tail -20', 'sh', 'linux', '[]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-top-cpu', 'snipf-proc', 'Top CPU consumers',
     'Processes sorted by CPU share',
     'ps -eo pid,user,pcpu,etimes,comm --sort=-pcpu | head -20', 'sh', 'linux', '[]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-proc-tree', 'snipf-proc', 'Process tree',
     'Parent and child relationships',
     'ps -ejH -o pid,ppid,user,comm | head -60', 'sh', 'linux', '[]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-listen', 'snipf-net', 'Listening sockets',
     'Which process owns which port',
     'ss -tulpn', 'sh', 'linux', '[]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-conns', 'snipf-net', 'Established connections by peer',
     'Counts remote addresses, useful when something is hammering the host',
     'ss -tn state established | awk ''NR>1 {split($4,a,":"); print a[1]}'' | sort | uniq -c | sort -rn | head -20',
     'bash', 'linux', '[]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-ip', 'snipf-net', 'Addresses and routes',
     'Interfaces, addresses, and the default route',
     'ip -br addr; echo; ip route', 'sh', 'linux', '[]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-port-check', 'snipf-net', 'Test a TCP port',
     'Check reachability of {target}:{port} from this host',
     'timeout 5 bash -c ''cat < /dev/null > /dev/tcp/{target}/{port}'' && echo open || echo closed',
     'bash', 'linux',
     '[{"name":"target","label":"Host","required":true},{"name":"port","label":"Port","default":"443","required":true}]',
     'insert', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-svc-status', 'snipf-systemd', 'Service status',
     'Full status for {service}',
     'systemctl status {service} --no-pager -l', 'sh', 'linux',
     '[{"name":"service","label":"Unit","default":"nginx","required":true}]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-svc-failed', 'snipf-systemd', 'Failed units',
     'Everything systemd could not start',
     'systemctl list-units --state=failed --no-pager', 'sh', 'linux', '[]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-svc-logs', 'snipf-systemd', 'Service logs',
     'Last 100 lines for {service}',
     'journalctl -u {service} -n 100 --no-pager', 'sh', 'linux',
     '[{"name":"service","label":"Unit","default":"nginx","required":true}]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-boot-time', 'snipf-systemd', 'Slowest units at boot',
     'Where startup time went',
     'systemd-analyze blame | head -20', 'sh', 'linux', '[]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-journal-errors', 'snipf-logs', 'Errors since boot',
     'Priority error and above from this boot',
     'journalctl -p err -b --no-pager | tail -100', 'sh', 'linux', '[]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-auth-fail', 'snipf-logs', 'Failed SSH logins',
     'Recent authentication failures',
     'journalctl -u ssh -u sshd --no-pager | grep -iE ''failed|invalid'' | tail -40', 'sh', 'linux', '[]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-docker-ps', 'snipf-docker', 'Containers',
     'Running containers with ports and status',
     'docker ps --format ''table {{.Names}}\t{{.Status}}\t{{.Ports}}\t{{.Image}}''', 'sh', 'linux', '[]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-docker-stats', 'snipf-docker', 'Container resource usage',
     'One-shot CPU and memory per container',
     'docker stats --no-stream', 'sh', 'linux', '[]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-docker-logs', 'snipf-docker', 'Container logs',
     'Last 200 lines from {container}',
     'docker logs --tail 200 --timestamps {container}', 'sh', 'linux',
     '[{"name":"container","label":"Container","required":true}]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-docker-df', 'snipf-docker', 'Docker disk usage',
     'Images, containers, and volumes by size',
     'docker system df -v', 'sh', 'linux', '[]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-k-pods', 'snipf-kube', 'Pods in a namespace',
     'Wide listing for {namespace}',
     'kubectl get pods -n {namespace} -o wide', 'sh', 'linux',
     '[{"name":"namespace","label":"Namespace","default":"default","required":true}]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-k-unhealthy', 'snipf-kube', 'Pods not running',
     'Everything that is not Running or Succeeded, across all namespaces',
     'kubectl get pods -A --field-selector=status.phase!=Running,status.phase!=Succeeded', 'sh', 'linux', '[]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-k-events', 'snipf-kube', 'Recent events',
     'Cluster events, newest last',
     'kubectl get events -n {namespace} --sort-by=.lastTimestamp | tail -40', 'sh', 'linux',
     '[{"name":"namespace","label":"Namespace","default":"default","required":true}]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-k-logs', 'snipf-kube', 'Pod logs',
     'Last 200 lines from {pod}',
     'kubectl logs -n {namespace} {pod} --tail 200', 'sh', 'linux',
     '[{"name":"namespace","label":"Namespace","default":"default","required":true},{"name":"pod","label":"Pod","required":true}]',
     'insert', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-nginx-test', 'snipf-nginx', 'Test configuration',
     'Validate before reloading -- always run this first',
     'nginx -t', 'sh', 'linux', '[]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-nginx-reload', 'snipf-nginx', 'Test then reload',
     'Reload only if the configuration parses',
     'nginx -t && systemctl reload nginx && echo reloaded', 'sh', 'linux', '[]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-nginx-top-ips', 'snipf-nginx', 'Top client addresses',
     'Busiest clients in {logfile}',
     'awk ''{print $1}'' {logfile} | sort | uniq -c | sort -rn | head -20', 'bash', 'linux',
     '[{"name":"logfile","label":"Access log","default":"/var/log/nginx/access.log","required":true}]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    ('snip-nginx-5xx', 'snipf-nginx', 'Recent 5xx responses',
     'Server errors from {logfile}',
     'awk ''$9 ~ /^5/ {print}'' {logfile} | tail -40', 'bash', 'linux',
     '[{"name":"logfile","label":"Access log","default":"/var/log/nginx/access.log","required":true}]', 'insert',
     strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now'));
