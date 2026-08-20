package api

import (
	"net/http"

	"github.com/axt-term/axt-term/backend/internal/credentials"
	"github.com/axt-term/axt-term/backend/internal/httpx"
	"github.com/axt-term/axt-term/backend/internal/store"
)

// Every response on this path carries metadata only. store.Credential has no
// field for a secret, so there is nothing here that could serialise one even by
// mistake -- the absence is the enforcement.

func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	creds, err := s.creds.List(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeList(w, creds, len(creds))
}

func (s *Server) handleGetCredential(w http.ResponseWriter, r *http.Request) {
	cred, err := s.creds.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, cred)
}

type createCredentialRequest struct {
	Name     string                     `json:"name"`
	Kind     store.CredentialKind       `json:"kind"`
	Provider store.CredentialProvider   `json:"provider,omitempty"`
	Username string                     `json:"username,omitempty"`
	Domain   string                     `json:"domain,omitempty"`
	Notes    string                     `json:"notes,omitempty"`

	// Write-only. Accepted here and never returned by any endpoint.
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

func (s *Server) handleCreateCredential(w http.ResponseWriter, r *http.Request) {
	var req createCredentialRequest
	if !decode(w, r, &req) {
		return
	}

	cred, err := s.creds.Create(r.Context(), credentials.CreateInput{
		Name:       req.Name,
		Kind:       req.Kind,
		Provider:   req.Provider,
		Username:   req.Username,
		Domain:     req.Domain,
		Notes:      req.Notes,
		Password:   req.Password,
		PrivateKey: req.PrivateKey,
		Passphrase: req.Passphrase,
		ActorID:    s.principal(r).UserID,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}

	// The audit detail records what kind of credential was created and its key
	// fingerprint, which is enough to trace it later, and nothing more.
	s.audit.Record(r, Entry{
		Action:   ActionCredentialCreate,
		Target:   cred.Name,
		Severity: store.SeverityNotice,
		Detail: map[string]any{
			"kind":            string(cred.Kind),
			"key_fingerprint": cred.KeyFingerprint,
			"has_password":    cred.HasPassword,
			"has_private_key": cred.HasPrivateKey,
		},
	})
	httpx.WriteJSON(w, http.StatusCreated, cred)
}

// updateCredentialRequest uses pointers so an omitted secret means "leave
// unchanged" and an explicit empty string means "clear".
//
// Without that distinction, an edit form that does not resend a password would
// silently delete it and break every host referencing the credential.
type updateCredentialRequest struct {
	Name     *string `json:"name,omitempty"`
	Username *string `json:"username,omitempty"`
	Domain   *string `json:"domain,omitempty"`
	Notes    *string `json:"notes,omitempty"`

	Password   *string `json:"password,omitempty"`
	PrivateKey *string `json:"private_key,omitempty"`
	Passphrase *string `json:"passphrase,omitempty"`
}

func (s *Server) handleUpdateCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req updateCredentialRequest
	if !decode(w, r, &req) {
		return
	}

	cred, err := s.creds.Update(r.Context(), id, credentials.UpdateInput{
		Name:       req.Name,
		Username:   req.Username,
		Domain:     req.Domain,
		Notes:      req.Notes,
		Password:   req.Password,
		PrivateKey: req.PrivateKey,
		Passphrase: req.Passphrase,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}

	// Rotating a credential must not leave pooled connections authenticated with
	// the previous secret.
	hosts, herr := s.store.HostsReferencingCredential(r.Context(), id)
	if herr == nil {
		for _, host := range hosts {
			s.closeHostConnections(host.ID)
		}
	}

	changed := []string{}
	if req.Password != nil {
		changed = append(changed, "password")
	}
	if req.PrivateKey != nil {
		changed = append(changed, "private_key")
	}
	if req.Passphrase != nil {
		changed = append(changed, "passphrase")
	}

	s.audit.Record(r, Entry{
		Action:   ActionCredentialUpdate,
		Target:   cred.Name,
		Severity: store.SeverityNotice,
		Detail:   map[string]any{"secret_fields_changed": changed},
	})
	httpx.WriteJSON(w, http.StatusOK, cred)
}

func (s *Server) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	force := queryBool(r, "force")

	cred, err := s.creds.Get(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.creds.Delete(r.Context(), id, force); err != nil {
		s.fail(w, r, err)
		return
	}

	s.audit.Record(r, Entry{
		Action:   ActionCredentialDelete,
		Target:   cred.Name,
		Severity: store.SeverityWarning,
		Detail:   map[string]any{"forced": force, "was_in_use_by": cred.InUseByCount},
	})
	httpx.NoContent(w)
}
