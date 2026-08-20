package api

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/axt-term/axt-term/backend/internal/httpx"
	"github.com/axt-term/axt-term/backend/internal/store"
	"github.com/axt-term/axt-term/backend/internal/validate"
	"github.com/google/uuid"
)

func (s *Server) handleListSnippets(w http.ResponseWriter, r *http.Request) {
	snippets, err := s.store.ListSnippets(r.Context(), store.SnippetFilter{
		Query:    r.URL.Query().Get("q"),
		FolderID: r.URL.Query().Get("folder_id"),
		OSFamily: r.URL.Query().Get("os_family"),
		Favorite: queryBool(r, "favorite"),
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeList(w, snippets, len(snippets))
}

func (s *Server) handleListSnippetFolders(w http.ResponseWriter, r *http.Request) {
	folders, err := s.store.ListSnippetFolders(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeList(w, folders, len(folders))
}

type snippetRequest struct {
	FolderID    string                  `json:"folder_id,omitempty"`
	Name        string                  `json:"name"`
	Description string                  `json:"description,omitempty"`
	Body        string                  `json:"body"`
	Shell       string                  `json:"shell,omitempty"`
	OSFamily    string                  `json:"os_family,omitempty"`
	Variables   []store.SnippetVariable `json:"variables,omitempty"`
	IsFavorite  bool                    `json:"is_favorite,omitempty"`
	Hotkey      string                  `json:"hotkey,omitempty"`
	RunMode     store.SnippetRunMode    `json:"run_mode,omitempty"`
}

func (req *snippetRequest) validate() *validate.Errors {
	v := &validate.Errors{}
	v.Check("name", validate.Name(req.Name, 120))
	if strings.TrimSpace(req.Body) == "" {
		v.Add("body", "required")
	}
	if len(req.Body) > 64*1024 {
		v.Add("body", "must be at most 64 KiB")
	}
	if req.Shell == "" {
		req.Shell = "sh"
	}
	switch req.Shell {
	case "sh", "bash", "zsh", "fish", "powershell", "cmd", "any":
	default:
		v.Add("shell", "must be sh, bash, zsh, fish, powershell, cmd, or any")
	}
	if req.RunMode == "" {
		// Insert is the default so a snippet lands on the prompt for review
		// rather than executing on click.
		req.RunMode = store.RunModeInsert
	}
	if req.RunMode != store.RunModeInsert && req.RunMode != store.RunModeRun {
		v.Add("run_mode", "must be insert or run")
	}
	for i, variable := range req.Variables {
		if err := validate.VariableName(variable.Name); err != nil {
			v.Add(fmt.Sprintf("variables[%d].name", i), err.Error())
		}
	}
	// Every placeholder in the body must be declared, otherwise rendering would
	// silently leave a literal {foo} in a command that then does the wrong thing.
	declared := make(map[string]bool, len(req.Variables))
	for _, variable := range req.Variables {
		declared[variable.Name] = true
	}
	for _, name := range placeholdersIn(req.Body) {
		if !declared[name] && !isContextVariable(name) {
			v.Add("variables", fmt.Sprintf("the body uses {%s} but it is not declared", name))
		}
	}
	return v
}

func (s *Server) handleCreateSnippet(w http.ResponseWriter, r *http.Request) {
	var req snippetRequest
	if !decode(w, r, &req) {
		return
	}
	if v := req.validate(); v.Any() {
		httpx.ValidationFailed(w, r, v.Map())
		return
	}

	snippet := &store.Snippet{
		ID:          uuid.NewString(),
		FolderID:    req.FolderID,
		Name:        strings.TrimSpace(req.Name),
		Description: req.Description,
		Body:        req.Body,
		Shell:       req.Shell,
		OSFamily:    req.OSFamily,
		Variables:   req.Variables,
		IsFavorite:  req.IsFavorite,
		Hotkey:      req.Hotkey,
		RunMode:     req.RunMode,
		CreatedBy:   s.principal(r).UserID,
	}
	if snippet.Variables == nil {
		snippet.Variables = []store.SnippetVariable{}
	}
	if err := s.store.CreateSnippet(r.Context(), snippet); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit.Success(r, ActionSnippetCreate, snippet.Name, nil)
	httpx.WriteJSON(w, http.StatusCreated, snippet)
}

func (s *Server) handleUpdateSnippet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req snippetRequest
	if !decode(w, r, &req) {
		return
	}
	if v := req.validate(); v.Any() {
		httpx.ValidationFailed(w, r, v.Map())
		return
	}

	snippet, err := s.store.SnippetByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	snippet.FolderID = req.FolderID
	snippet.Name = strings.TrimSpace(req.Name)
	snippet.Description = req.Description
	snippet.Body = req.Body
	snippet.Shell = req.Shell
	snippet.OSFamily = req.OSFamily
	snippet.Variables = req.Variables
	snippet.IsFavorite = req.IsFavorite
	snippet.Hotkey = req.Hotkey
	snippet.RunMode = req.RunMode
	if snippet.Variables == nil {
		snippet.Variables = []store.SnippetVariable{}
	}

	if err := s.store.UpdateSnippet(r.Context(), snippet); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit.Success(r, ActionSnippetUpdate, snippet.Name, nil)
	httpx.WriteJSON(w, http.StatusOK, snippet)
}

func (s *Server) handleDeleteSnippet(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteSnippet(r.Context(), r.PathValue("id")); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit.Success(r, ActionSnippetDelete, r.PathValue("id"), nil)
	httpx.NoContent(w)
}

type renderSnippetRequest struct {
	HostID string            `json:"host_id,omitempty"`
	Vars   map[string]string `json:"vars,omitempty"`
}

type renderSnippetResponse struct {
	Text    string               `json:"text"`
	RunMode store.SnippetRunMode `json:"run_mode"`
	// Missing lists variables the caller still has to supply, so the UI knows to
	// prompt rather than sending a half-rendered command.
	Missing []string `json:"missing,omitempty"`
}

// handleRenderSnippet resolves variables and returns text.
//
// It never executes. Rendering and running are separate operations, and that
// separation is what makes "insert, review, press Enter" the default path for a
// tool that has root on the machines it talks to.
func (s *Server) handleRenderSnippet(w http.ResponseWriter, r *http.Request) {
	var req renderSnippetRequest
	if !decode(w, r, &req) {
		return
	}

	snippet, err := s.store.SnippetByID(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}

	context := map[string]string{}
	if req.HostID != "" {
		host, herr := s.store.HostByID(r.Context(), req.HostID)
		if herr != nil {
			s.fail(w, r, herr)
			return
		}
		context["host"] = host.Name
		context["hostname"] = host.Hostname
		context["port"] = strconv.Itoa(host.Port)
		context["username"] = host.Username
		context["folder"] = host.FolderPath
		context["address"] = host.Address()
	}
	context["user"] = s.principal(r).Username

	text, missing := renderSnippet(snippet, context, req.Vars)
	if len(missing) == 0 {
		if err := s.store.IncrementSnippetUse(r.Context(), snippet.ID); err != nil {
			s.log.WarnContext(r.Context(), "could not increment snippet use count")
		}
	}

	httpx.WriteJSON(w, http.StatusOK, renderSnippetResponse{
		Text:    text,
		RunMode: snippet.RunMode,
		Missing: missing,
	})
}

var placeholderPattern = regexp.MustCompile(`\{([a-z_][a-z0-9_]{0,63})\}`)

func placeholdersIn(body string) []string {
	matches := placeholderPattern.FindAllStringSubmatch(body, -1)
	seen := make(map[string]bool, len(matches))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

// isContextVariable reports whether a placeholder is filled automatically from
// the active host rather than declared on the snippet.
func isContextVariable(name string) bool {
	switch name {
	case "host", "hostname", "port", "username", "user", "folder", "address":
		return true
	}
	return false
}

// renderSnippet substitutes placeholders, reporting any that remain unfilled.
func renderSnippet(snippet *store.Snippet, context, supplied map[string]string) (string, []string) {
	values := make(map[string]string, len(context)+len(supplied)+len(snippet.Variables))

	// Precedence: declared defaults, then host context, then what the user typed.
	for _, variable := range snippet.Variables {
		if variable.Default != "" {
			values[variable.Name] = variable.Default
		}
		if variable.Source != "" {
			if v, ok := context[variable.Source]; ok && v != "" {
				values[variable.Name] = v
			}
		}
	}
	for k, v := range context {
		if v != "" {
			values[k] = v
		}
	}
	for k, v := range supplied {
		if v != "" {
			values[k] = v
		}
	}

	missingSet := map[string]bool{}
	text := placeholderPattern.ReplaceAllStringFunc(snippet.Body, func(match string) string {
		name := match[1 : len(match)-1]
		if v, ok := values[name]; ok {
			return v
		}
		missingSet[name] = true
		// The placeholder is left in place: emitting an empty string would turn
		// `rm -rf {path}` into `rm -rf `, which is a different and much worse
		// command than an obviously unfinished one.
		return match
	})

	missing := make([]string, 0, len(missingSet))
	for name := range missingSet {
		missing = append(missing, name)
	}
	sort.Strings(missing)
	return text, missing
}
