package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"proxy-dispatcher/internal/auth"
)

type ctxKey string

const ctxKeyUser ctxKey = "username"

type authCtxKey struct{}

var publicEndpoints = map[string]bool{
	"POST /api/login":        true,
	"POST /api/login/totp":   true,
	"POST /api/sync/receive": true,
}

func isPublicEndpoint(method, path string) bool {
	return publicEndpoints[method+" "+path]
}

// AuthMiddleware builds an http middleware that authenticates via JWT or API
// token and enforces endpoint permissions (Phase 6).
func AuthMiddleware(userMgr *auth.UserManager, tokenMgr *auth.TokenManager, jwtSecret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/ws/") {
				next.ServeHTTP(w, r)
				return
			}
			if isPublicEndpoint(r.Method, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			authCtx, err := resolveAuth(r, userMgr, tokenMgr, jwtSecret)
			if err != nil || authCtx == nil {
				respondError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			required := auth.MatchEndpointPermission(r.Method, r.URL.Path)
			if required != "" && !auth.HasPermission(authCtx, required) {
				respondError(w, http.StatusForbidden, "forbidden: need "+required)
				return
			}
			ctx := context.WithValue(r.Context(), authCtxKey{}, authCtx)
			ctx = context.WithValue(ctx, ctxKeyUser, authCtx.Username)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func resolveAuth(r *http.Request, userMgr *auth.UserManager, tokenMgr *auth.TokenManager, jwtSecret string) (*auth.AuthContext, error) {
	if raw := r.Header.Get("X-API-Token"); raw != "" && tokenMgr != nil {
		t, err := tokenMgr.ValidateToken(raw)
		if err != nil {
			return nil, err
		}
		return &auth.AuthContext{
			AuthType: "token", Username: t.CreatedBy,
			Permissions: t.Permissions, TokenID: t.ID,
		}, nil
	}
	header := r.Header.Get("Authorization")
	var tokenStr string
	if strings.HasPrefix(header, "Bearer ") {
		tokenStr = strings.TrimPrefix(header, "Bearer ")
	} else if q := r.URL.Query().Get("token"); q != "" {
		tokenStr = q
	}
	if tokenStr == "" {
		return nil, http.ErrNoCookie
	}
	claims, err := auth.ValidateTokenClaims(tokenStr, jwtSecret)
	if err != nil {
		return nil, err
	}
	if stage, _ := claims["stage"].(string); stage != "" && stage != "full" {
		return nil, http.ErrNoCookie
	}
	uname, _ := claims["username"].(string)
	if uname == "" {
		return nil, http.ErrNoCookie
	}
	var role string
	if userMgr != nil {
		if u := userMgr.GetUser(uname); u != nil {
			if u.Disabled {
				return nil, http.ErrNoCookie
			}
			role = u.Role
		}
	}
	if role == "" {
		role = "admin"
	}
	return &auth.AuthContext{
		AuthType: "jwt", Username: uname, Role: role,
		Permissions: auth.ExpandRole(role),
	}, nil
}

// GetAuthContext extracts the AuthContext from a request.
func GetAuthContext(r *http.Request) *auth.AuthContext {
	v := r.Context().Value(authCtxKey{})
	if v == nil {
		return nil
	}
	return v.(*auth.AuthContext)
}

// authRequired wraps next with Bearer-token validation (legacy Phase 1).
func (s *Server) authRequired(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			respondError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		token := strings.TrimPrefix(h, "Bearer ")
		uname, err := auth.ValidateToken(token, s.cfg.JwtSecret)
		if err != nil {
			respondError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeyUser, uname)
		next(w, r.WithContext(ctx))
	}
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, msg string) {
	respondJSON(w, status, map[string]string{"error": msg})
}

func getClientIP(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		if i := strings.Index(xf, ","); i >= 0 {
			return strings.TrimSpace(xf[:i])
		}
		return strings.TrimSpace(xf)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
