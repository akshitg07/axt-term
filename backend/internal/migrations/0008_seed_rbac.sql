-- 0008: seed the permission registry and built-in roles.
--
-- The distinction that matters here is credential.use versus credential.read: an
-- operator can connect with a stored credential without being able to retrieve
-- or export its secret.

INSERT INTO permissions (key, description) VALUES
    ('host.read',         'View hosts, folders, and tags'),
    ('host.write',        'Create, edit, and delete hosts, folders, and tags'),
    ('host.discover',     'Run network discovery scans'),
    ('credential.use',    'Connect using stored credentials without reading them'),
    ('credential.read',   'View credential metadata'),
    ('credential.write',  'Create, edit, and delete credentials'),
    ('session.ssh',       'Open SSH terminal sessions'),
    ('session.rdp',       'Open RDP and VNC sessions'),
    ('session.record',    'Start and download session recordings'),
    ('file.read',         'Browse and download remote files'),
    ('file.write',        'Upload, edit, rename, and delete remote files'),
    ('exec.batch',        'Run commands across multiple hosts'),
    ('snippet.read',      'View command snippets'),
    ('snippet.write',     'Create, edit, and delete command snippets'),
    ('tunnel.read',       'View SSH tunnels'),
    ('tunnel.write',      'Create, start, stop, and delete SSH tunnels'),
    ('service.read',      'View system services and processes'),
    ('service.write',     'Start, stop, restart services and signal processes'),
    ('docker.read',       'View Docker resources'),
    ('docker.write',      'Manage Docker containers and images'),
    ('kube.read',         'View Kubernetes resources'),
    ('kube.write',        'Manage Kubernetes workloads'),
    ('workspace.manage',  'Save and restore workspaces'),
    ('admin.users',       'Manage users and role assignments'),
    ('admin.audit',       'Search and export the audit log'),
    ('admin.settings',    'Change instance settings'),
    ('admin.hostkeys',    'Revoke trusted SSH host keys');

INSERT INTO roles (id, name, description, is_builtin) VALUES
    ('role-admin',    'admin',    'Full access, including users, audit, and settings', 1),
    ('role-operator', 'operator', 'Day-to-day infrastructure work; cannot read credential secrets or manage users', 1),
    ('role-viewer',   'viewer',   'Read-only inventory and snippets, plus shell access', 1);

-- admin holds everything.
INSERT INTO role_permissions (role_id, permission_key)
    SELECT 'role-admin', key FROM permissions;

INSERT INTO role_permissions (role_id, permission_key) VALUES
    ('role-operator', 'host.read'),
    ('role-operator', 'host.write'),
    ('role-operator', 'host.discover'),
    ('role-operator', 'credential.use'),
    ('role-operator', 'credential.read'),
    ('role-operator', 'session.ssh'),
    ('role-operator', 'session.rdp'),
    ('role-operator', 'session.record'),
    ('role-operator', 'file.read'),
    ('role-operator', 'file.write'),
    ('role-operator', 'exec.batch'),
    ('role-operator', 'snippet.read'),
    ('role-operator', 'snippet.write'),
    ('role-operator', 'tunnel.read'),
    ('role-operator', 'tunnel.write'),
    ('role-operator', 'service.read'),
    ('role-operator', 'service.write'),
    ('role-operator', 'docker.read'),
    ('role-operator', 'docker.write'),
    ('role-operator', 'kube.read'),
    ('role-operator', 'kube.write'),
    ('role-operator', 'workspace.manage');

-- A viewer still gets a shell, because a read-only shell is the normal way to
-- inspect a system. Genuine read-only enforcement belongs on the target host,
-- and the UI says so rather than implying a guarantee it cannot make.
INSERT INTO role_permissions (role_id, permission_key) VALUES
    ('role-viewer', 'host.read'),
    ('role-viewer', 'credential.use'),
    ('role-viewer', 'session.ssh'),
    ('role-viewer', 'file.read'),
    ('role-viewer', 'snippet.read'),
    ('role-viewer', 'service.read'),
    ('role-viewer', 'docker.read'),
    ('role-viewer', 'kube.read'),
    ('role-viewer', 'workspace.manage');
