package httpx

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Access declares how a route is protected.
//
// The zero value is deliberately invalid. If AccessPublic were zero, forgetting
// the field on a new route would silently publish it, which is exactly the
// mistake the security architecture promises to make impossible. Validate
// rejects an unset value, so the omission becomes a startup failure.
type Access int

const (
	accessUnset Access = iota
	// AccessPublic requires no authentication. Reserved for health checks, the
	// login endpoint, and static assets.
	AccessPublic
	// AccessAuthenticated requires a valid browser session but no specific
	// permission.
	AccessAuthenticated
	// AccessPermission requires a valid session holding Permission.
	AccessPermission
)

func (a Access) String() string {
	switch a {
	case AccessPublic:
		return "public"
	case AccessAuthenticated:
		return "authenticated"
	case AccessPermission:
		return "permission"
	default:
		return "unset"
	}
}

// Route describes one endpoint and how it is protected.
type Route struct {
	Method  string
	Pattern string
	Access  Access
	// Permission is required when Access is AccessPermission and must be empty
	// otherwise.
	Permission string
	// Streaming marks routes that must not be wrapped in request timeouts or
	// body limits: WebSocket upgrades, file downloads, and file uploads.
	Streaming bool
	// Summary is a short description, used by the route listing.
	Summary string
}

// routeEntry pairs a handler with the declaration that protects it.
type routeEntry struct {
	handler http.Handler
	route   Route
}

// Router maps method and pattern to handlers, and records how each route is
// protected so the set can be validated at startup and audited later.
type Router struct {
	global   []Middleware
	routes   []Route
	handlers map[string]map[string]routeEntry // pattern -> method -> entry
	// Authorize, when set, produces the per-route permission check. It is applied
	// when Handler builds the tree, so a route physically cannot be served
	// without its declared check having run.
	Authorize func(access Access, permission string) Middleware
	// NotFound handles unmatched paths. In production this is the SPA fallback;
	// it defaults to a JSON 404.
	NotFound http.Handler
	errs     []error
}

// NewRouter creates a router whose global middleware wraps every route,
// including the not-found handler.
func NewRouter(global ...Middleware) *Router {
	return &Router{
		global:   global,
		handlers: make(map[string]map[string]routeEntry),
	}
}

// Handle registers a route. Route-specific middleware runs inside the global
// chain, in the order given.
func (rt *Router) Handle(route Route, h http.Handler, mw ...Middleware) {
	if route.Method == "" || route.Pattern == "" {
		rt.errs = append(rt.errs, fmt.Errorf("route %+v: method and pattern are required", route))
		return
	}
	method := strings.ToUpper(route.Method)
	route.Method = method

	byMethod, ok := rt.handlers[route.Pattern]
	if !ok {
		byMethod = make(map[string]routeEntry)
		rt.handlers[route.Pattern] = byMethod
	}
	if _, exists := byMethod[method]; exists {
		rt.errs = append(rt.errs, fmt.Errorf("duplicate route %s %s", method, route.Pattern))
		return
	}

	byMethod[method] = routeEntry{handler: Chain(h, mw...), route: route}
	rt.routes = append(rt.routes, route)
}

// HandleFunc is Handle for a function handler.
func (rt *Router) HandleFunc(route Route, h http.HandlerFunc, mw ...Middleware) {
	rt.Handle(route, h, mw...)
}

// Routes returns every registered route, sorted for stable output.
func (rt *Router) Routes() []Route {
	out := make([]Route, len(rt.routes))
	copy(out, rt.routes)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Pattern != out[j].Pattern {
			return out[i].Pattern < out[j].Pattern
		}
		return out[i].Method < out[j].Method
	})
	return out
}

// Validate reports registration problems. permissionExists, when non-nil, is
// consulted to confirm each declared permission is one the RBAC registry knows;
// passing nil skips that check, which is what the M1 server does before the
// registry exists.
//
// Startup calls this and refuses to serve on error. An endpoint that forgot to
// declare its protection therefore fails the deployment instead of shipping
// unprotected.
func (rt *Router) Validate(permissionExists func(string) bool) error {
	errs := append([]error(nil), rt.errs...)

	for _, r := range rt.routes {
		id := r.Method + " " + r.Pattern
		switch r.Access {
		case accessUnset:
			errs = append(errs, fmt.Errorf("%s: no Access declared; every route must state whether it is public, authenticated, or permission-gated", id))
		case AccessPermission:
			if r.Permission == "" {
				errs = append(errs, fmt.Errorf("%s: Access is AccessPermission but Permission is empty", id))
			} else if permissionExists != nil && !permissionExists(r.Permission) {
				errs = append(errs, fmt.Errorf("%s: unknown permission %q", id, r.Permission))
			}
		case AccessPublic, AccessAuthenticated:
			if r.Permission != "" {
				errs = append(errs, fmt.Errorf("%s: Permission %q is set but Access is %s", id, r.Permission, r.Access))
			}
		}
	}

	if len(errs) == 0 {
		return nil
	}
	msgs := make([]string, len(errs))
	for i, e := range errs {
		msgs[i] = e.Error()
	}
	sort.Strings(msgs)
	return errors.New("invalid route table:\n  - " + strings.Join(msgs, "\n  - "))
}

// Handler builds the servable handler.
//
// One dispatcher is registered per pattern rather than relying on the standard
// mux's method matching, so that a method mismatch yields the same JSON error
// shape as everything else, with a correct Allow header.
func (rt *Router) Handler() http.Handler {
	mux := http.NewServeMux()

	for pattern, byMethod := range rt.handlers {
		mux.Handle(pattern, rt.dispatcher(byMethod))
	}

	if _, hasRoot := rt.handlers["/"]; !hasRoot {
		nf := rt.NotFound
		if nf == nil {
			nf = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				NotFound(w, r, "endpoint")
			})
		}
		mux.Handle("/", nf)
	}

	return Chain(mux, rt.global...)
}

func (rt *Router) dispatcher(byMethod map[string]routeEntry) http.Handler {
	// Wrap each handler in its declared authorisation check as the tree is built,
	// so serving a route without its check is not expressible.
	resolved := make(map[string]http.Handler, len(byMethod))
	for method, entry := range byMethod {
		h := entry.handler
		if rt.Authorize != nil {
			h = rt.Authorize(entry.route.Access, entry.route.Permission)(h)
		}
		resolved[method] = h
	}

	allow := make([]string, 0, len(resolved)+2)
	for m := range resolved {
		allow = append(allow, m)
	}
	if _, hasGet := resolved[http.MethodGet]; hasGet {
		if _, hasHead := resolved[http.MethodHead]; !hasHead {
			allow = append(allow, http.MethodHead)
		}
	}
	allow = append(allow, http.MethodOptions)
	sort.Strings(allow)
	allowHeader := strings.Join(allow, ", ")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, ok := resolved[r.Method]; ok {
			h.ServeHTTP(w, r)
			return
		}
		// HEAD falls back to GET; net/http discards the body for us.
		if r.Method == http.MethodHead {
			if h, ok := resolved[http.MethodGet]; ok {
				h.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("Allow", allowHeader)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		WriteError(w, r, http.StatusMethodNotAllowed, CodeMethodNotAllowed,
			"method "+r.Method+" is not allowed for this endpoint")
	})
}
