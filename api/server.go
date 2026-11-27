package api

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Server struct {
	store       *Store
	httpServer  *http.Server
	loginMu     sync.Mutex
	loginCounts map[string]*loginAttempt
}

type loginAttempt struct {
	count     int
	lastAttempt time.Time
}

func NewServer(addr, dataDir string) (*Server, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}

	store, err := NewStore(filepath.Join(dataDir, "panel.db"))
	if err != nil {
		return nil, err
	}

	server := &Server{
		store:       store,
		loginCounts: make(map[string]*loginAttempt),
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", server.handleHealth)
	mux.HandleFunc("POST /api/auth/setup", server.handleSetup)
	mux.HandleFunc("POST /api/auth/login", server.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", server.requireRole("admin", "researcher", "auditor")(server.handleLogout))
	mux.HandleFunc("GET /api/auth/me", server.requireRole("admin", "researcher", "auditor")(server.handleMe))
	mux.HandleFunc("POST /api/auth/change-password", server.requireRole("admin", "researcher", "auditor")(server.handleChangePassword))

	mux.Handle("GET /api/metrics", server.requireRole("admin", "researcher", "auditor")(server.handleMetrics))
	mux.Handle("POST /api/metrics/research-event", server.requireRole("admin", "researcher")(server.handleResearchEvent))
	mux.Handle("GET /api/audit", server.requireRole("admin", "auditor")(server.handleAudit))
	mux.Handle("GET /api/config", server.requireRole("admin")(server.handleConfig))

	mux.Handle("/", server.requireRole("admin", "researcher", "auditor")(
		http.FileServer(http.Dir("./web")),
	))

	server.httpServer = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return server, nil
}

func (s *Server) Start() error {
	log.Printf("Research control panel listening on %s", s.httpServer.Addr)
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) Close() error {
	return s.store.Close()
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "evilginx-research-control-panel",
	})
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	admins, err := s.store.CountAdmins()

	if err != nil {
		writeError(w, http.StatusInternalServerError, "database_error")
		return
	}

	if admins > 0 {
		writeError(w, http.StatusForbidden, "setup_already_completed")
		return
	}

	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := decodeJSON(w, r, &input); err != nil {
		return
	}

	username := normalizeUsername(input.Username)

	if len(username) < 3 || len(username) > 64 || !validPassword(input.Password) {
		writeError(w, http.StatusBadRequest, "invalid_username_or_password")
		return
	}

	passwordHash, err := hashPassword(input.Password)

	if err != nil {
		writeError(w, http.StatusInternalServerError, "hashing_error")
		return
	}

	if err := s.store.CreateUser(username, passwordHash, "admin"); err != nil {
		writeError(w, http.StatusInternalServerError, "account_creation_failed")
		return
	}

	_ = s.store.RecordAudit(username, "admin_created", "Initial administrator account created")

	writeJSON(w, http.StatusCreated, map[string]string{"status": "administrator_created"})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := decodeJSON(w, r, &input); err != nil {
		return
	}

	username := normalizeUsername(input.Username)
	key := clientKey(r, username)

	if !s.allowLoginAttempt(key) {
		writeError(w, http.StatusTooManyRequests, "too_many_attempts")
		return
	}

	user, err := s.store.GetUserByUsername(username)

	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_username_or_password")
		return
	}

	if time.Now().Before(user.LockedUntil) {
		writeError(w, http.StatusTooManyRequests, "account_temporarily_locked")
		return
	}

	if !verifyPassword(input.Password, user.PasswordHash) {
		lockedUntil := time.Now().Add(lockoutDuration)

		if user.FailedLoginAttempts+1 < maxLoginAttempts {
			lockedUntil = time.Time{}
		}

		_ = s.store.RecordFailedLogin(user.ID, lockedUntil)
		writeError(w, http.StatusUnauthorized, "invalid_username_or_password")
		return
	}

	token, err := randomToken()

	if err != nil {
		writeError(w, http.StatusInternalServerError, "session_creation_failed")
		return
	}

	csrfToken, err := randomToken()

	if err != nil {
		writeError(w, http.StatusInternalServerError, "session_creation_failed")
		return
	}

	expires := time.Now().Add(sessionLifetime)

	if err := s.store.CreateSession(
		user.ID,
		hashToken(token),
		csrfToken,
		expires,
	); err != nil {
		writeError(w, http.StatusInternalServerError, "session_creation_failed")
		return
	}

	_ = s.store.RecordSuccessfulLogin(user.ID)
	_ = s.store.RecordAudit(user.Username, "login", "Successful control-panel login")

	s.setSessionCookie(w, token, expires)

	writeJSON(w, http.StatusOK, map[string]any{
		"username":    user.Username,
		"role":        user.Role,
		"csrf_token":  csrfToken,
		"expires_at":  expires.UTC(),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)

	if err == nil {
		_ = s.store.DeleteSession(hashToken(cookie.Value))
	}

	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	session, err := s.currentSession(r)

	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication_required")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"username": session.User.Username,
		"role":     session.User.Role,
	})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	session, err := s.currentSession(r)

	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication_required")
		return
	}

	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}

	if err := decodeJSON(w, r, &input); err != nil {
		return
	}

	user, err := s.store.GetUserByUsername(session.User.Username)

	if err != nil || !verifyPassword(input.CurrentPassword, user.PasswordHash) {
		writeError(w, http.StatusUnauthorized, "invalid_current_password")
		return
	}

	if !validPassword(input.NewPassword) {
		writeError(w, http.StatusBadRequest, "invalid_new_password")
		return
	}

	newHash, err := hashPassword(input.NewPassword)

	if err != nil {
		writeError(w, http.StatusInternalServerError, "hashing_error")
		return
	}

	if err := s.store.UpdatePassword(user.ID, newHash); err != nil {
		writeError(w, http.StatusInternalServerError, "password_update_failed")
		return
	}

	_ = s.store.DeleteSessionsForUser(user.ID)
	_ = s.store.RecordAudit(user.Username, "password_changed", "Password changed; all sessions revoked")

	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "password_changed"})
}

func (s *Server) allowLoginAttempt(key string) bool {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()

	now := time.Now()
	attempt := s.loginCounts[key]

	if attempt == nil || now.Sub(attempt.lastAttempt) > time.Minute {
		s.loginCounts[key] = &loginAttempt{count: 1, lastAttempt: now}
		return true
	}

	attempt.count++
	attempt.lastAttempt = now

	return attempt.count <= 10
}

func clientKey(r *http.Request, username string) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)

	if err != nil {
		host = r.RemoteAddr
	}

	return host + "|" + username
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 8192)

	if err := json.NewDecoder(r.Body).Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return err
	}

	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}
