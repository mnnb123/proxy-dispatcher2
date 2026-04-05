package auth

import (
	"strings"
)

// AuthContext carries per-request authentication information.
type AuthContext struct {
	AuthType    string
	Username    string
	Role        string
	Permissions []string
	TokenID     string
}

// RolePermissions maps role → granted permissions.
var RolePermissions = map[string][]string{
	"admin": {"*"},
	"operator": {
		"read:config", "write:config",
		"read:proxy", "write:proxy",
		"read:rules", "write:rules",
		"read:report", "read:health",
		"read:groups", "write:groups",
		"read:system",
	},
	"viewer": {
		"read:config", "read:proxy", "read:rules",
		"read:report", "read:health", "read:groups", "read:system",
	},
}

// EndpointPermissions maps route patterns → required permission.
var EndpointPermissions = map[string]string{
	"GET /api/me":               "read:self",
	"POST /api/me/*":            "write:self",
	"POST /api/password":        "write:self",
	"GET /api/status":           "read:status",
	"GET /api/config/*":         "read:config",
	"POST /api/config/*":        "write:config",
	"DELETE /api/config/*":      "write:config",
	"GET /api/groups":           "read:groups",
	"GET /api/groups/*":         "read:groups",
	"POST /api/groups":          "write:groups",
	"PUT /api/groups/*":         "write:groups",
	"DELETE /api/groups/*":      "write:groups",
	"GET /api/port-mappings":    "read:groups",
	"POST /api/port-mappings":   "write:groups",
	"GET /api/import/*":         "read:groups",
	"POST /api/import/*":        "write:groups",
	"DELETE /api/import/*":      "write:groups",
	"GET /api/health/*":         "read:health",
	"POST /api/health/*":        "write:health",
	"GET /api/bandwidth/*":      "read:report",
	"GET /api/report/*":         "read:report",
	"POST /api/report/*":        "write:report",
	"GET /api/users":            "read:users",
	"POST /api/users":           "write:users",
	"PUT /api/users/*":          "write:users",
	"DELETE /api/users/*":       "write:users",
	"GET /api/tokens":           "read:tokens",
	"POST /api/tokens":          "write:tokens",
	"DELETE /api/tokens/*":      "write:tokens",
	"GET /api/sync/*":           "read:sync",
	"POST /api/sync/push":       "write:sync",
	"GET /api/system/*":         "read:system",
	"POST /api/system/*":        "write:system",
}

// MatchEndpointPermission returns the required permission for a method+path.
func MatchEndpointPermission(method, path string) string {
	key := method + " " + path
	if p, ok := EndpointPermissions[key]; ok {
		return p
	}
	// Wildcard match by progressively trimming path segments.
	for pattern, perm := range EndpointPermissions {
		if !strings.HasSuffix(pattern, "/*") {
			continue
		}
		prefix := strings.TrimSuffix(pattern, "*")
		full := method + " " + path
		if strings.HasPrefix(full, prefix) {
			return perm
		}
	}
	return ""
}

// HasPermission checks whether the AuthContext grants perm.
func HasPermission(authCtx *AuthContext, perm string) bool {
	if authCtx == nil {
		return false
	}
	if perm == "" {
		return true
	}
	for _, p := range authCtx.Permissions {
		if p == "*" || p == perm {
			return true
		}
		if strings.HasSuffix(p, ":*") {
			prefix := strings.TrimSuffix(p, "*")
			if strings.HasPrefix(perm, prefix) {
				return true
			}
		}
	}
	return false
}

// ExpandRole returns the permission list for a role (flattened).
func ExpandRole(role string) []string {
	if perms, ok := RolePermissions[role]; ok {
		return perms
	}
	return nil
}
