// Package rbac holds the canonical permission registry.
//
// The keys are declared here as Go constants and seeded into the database by
// migration 0008. Two consistency checks depend on this duplication being
// verified rather than assumed:
//
//   - httpx.Router.Validate rejects a route declaring a permission that is not in
//     this list, so a typo in a route table fails startup rather than silently
//     denying every request.
//   - VerifyAgainstStore compares this list with the seeded rows at startup, so a
//     migration and a code change that drift apart are caught immediately.
package rbac

import (
	"fmt"
	"sort"
)

// Permission keys. Grouped by the resource they govern.
const (
	HostRead     = "host.read"
	HostWrite    = "host.write"
	HostDiscover = "host.discover"

	// CredentialUse permits connecting with a stored credential.
	// CredentialRead permits seeing its metadata. Neither permits retrieving a
	// secret, because no endpoint can do that at all.
	CredentialUse   = "credential.use"
	CredentialRead  = "credential.read"
	CredentialWrite = "credential.write"

	SessionSSH    = "session.ssh"
	SessionRDP    = "session.rdp"
	SessionRecord = "session.record"

	FileRead  = "file.read"
	FileWrite = "file.write"

	ExecBatch = "exec.batch"

	SnippetRead  = "snippet.read"
	SnippetWrite = "snippet.write"

	TunnelRead  = "tunnel.read"
	TunnelWrite = "tunnel.write"

	ServiceRead  = "service.read"
	ServiceWrite = "service.write"

	DockerRead  = "docker.read"
	DockerWrite = "docker.write"

	KubeRead  = "kube.read"
	KubeWrite = "kube.write"

	WorkspaceManage = "workspace.manage"

	AdminUsers    = "admin.users"
	AdminAudit    = "admin.audit"
	AdminSettings = "admin.settings"
	AdminHostKeys = "admin.hostkeys"
)

// Built-in role names.
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

// all is every permission this build knows about.
var all = []string{
	HostRead, HostWrite, HostDiscover,
	CredentialUse, CredentialRead, CredentialWrite,
	SessionSSH, SessionRDP, SessionRecord,
	FileRead, FileWrite,
	ExecBatch,
	SnippetRead, SnippetWrite,
	TunnelRead, TunnelWrite,
	ServiceRead, ServiceWrite,
	DockerRead, DockerWrite,
	KubeRead, KubeWrite,
	WorkspaceManage,
	AdminUsers, AdminAudit, AdminSettings, AdminHostKeys,
}

var index = func() map[string]struct{} {
	m := make(map[string]struct{}, len(all))
	for _, p := range all {
		m[p] = struct{}{}
	}
	return m
}()

// All returns every permission key, sorted.
func All() []string {
	out := make([]string, len(all))
	copy(out, all)
	sort.Strings(out)
	return out
}

// Exists reports whether a key is a known permission. Passed to
// httpx.Router.Validate so an unknown permission on a route fails startup.
func Exists(key string) bool {
	_, ok := index[key]
	return ok
}

// VerifyAgainstKeys compares the code's registry with the keys the database holds.
//
// Called at startup with the seeded keys. Drift in either direction is a bug: a
// key in the database but not in code means a route can never reference it, and a
// key in code but not the database means role assignment cannot grant it.
func VerifyAgainstKeys(dbKeys []string) error {
	inDB := make(map[string]struct{}, len(dbKeys))
	for _, k := range dbKeys {
		inDB[k] = struct{}{}
	}

	var missingInDB, missingInCode []string
	for _, k := range all {
		if _, ok := inDB[k]; !ok {
			missingInDB = append(missingInDB, k)
		}
	}
	for _, k := range dbKeys {
		if !Exists(k) {
			missingInCode = append(missingInCode, k)
		}
	}

	if len(missingInDB) == 0 && len(missingInCode) == 0 {
		return nil
	}
	sort.Strings(missingInDB)
	sort.Strings(missingInCode)
	return fmt.Errorf(
		"permission registry drift: declared in code but not seeded in the database %v; "+
			"seeded in the database but unknown to this build %v",
		missingInDB, missingInCode)
}
