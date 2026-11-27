package api

import (
	"context"
	"net/http"
	"time"
)

type Server struct {
	addr  string
	store *Store
	http  *http.Server
}

func NewServer(addr, usersPath string) (*Server, error) {
	store, err := NewStore(usersPath)
	if err != nil {
		return nil, err
	}

	server := &Server{
		addr:  addr,
		store: store,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/health", server.health)
	mux.HandleFunc("GET /api/auth/status", server.authStatus)
	mux.HandleFunc("POST /api/auth/register", server.register)
	mux.HandleFunc("POST /api/auth/login", server.login)
	mux.HandleFunc("POST /api/auth/logout", server.requireAuth(server.logout))
	mux.HandleFunc("GET /api/auth/me", server.requireAuth(server.currentUser))
	mux.HandleFunc("POST /api/auth/change-password", server.requireAuth(server.changePassword))

	mux.HandleFunc("GET /api/config", server.requireAuth(server.getConfig))
	mux.HandleFunc("GET /api/metrics", server.requireAuth(server.getMetrics))
	mux.HandleFunc("POST /api/metrics/research-event", server.requireAuth(server.recordResearchEvent))
	mux.HandleFunc("GET /api/audit", server.requireAuth(server.getAudit))

	mux.Handle("/", server.requireAuthHandler(http.FileServer(http.Dir("./web"))))

	server.http = &http.Server{
		Addr:              addr,
		Handler:           server.securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	return server, nil
}

func (s *Server) Start() error {
	return s.http.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set(
			"Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'",
		)

		next.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "evilginx-research-control-panel",
	})
}

func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{
		"setup_required": !s.store.HasUsers(),
	})
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if s.store.HasUsers() {
		writeError(w, http.StatusForbidden, "setup_already_completed")
		return
	}

	var input struct {
		Username        string `json:"username"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirm_password"`
	}

	if err := readJSON(w, r, &input); err != nil {
		return
	}

	if input.Password != input.ConfirmPassword {
		writeError(w, http.StatusBadRequest, "passwords_do_not_match")
		return
	}

	if err := s.store.CreateUser(input.Username, input.Password, "admin"); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.store.RecordAudit(input.Username, "initial_admin_created", "")

	writeJSON(w, http.StatusCreated, map[string]string{
		"status": "administrator_created",
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := readJSON(w, r, &input); err != nil {
		return
	}

	clientIP := clientIP(r)

	user, err := s.store.Authenticate(input.Username, input.Password, clientIP)
	if err != nil {
		s.store.RecordAudit("anonymous", "login_failed", clientIP)
		writeError(w, http.StatusUnauthorized, "invalid_username_or_password")
		return
	}

	session, err := s.store.CreateSession(user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session_creation_failed")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    session.Token,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionExpiresIn.Seconds()),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    session.CSRFToken,
		Path:     "/",
		HttpOnly: false,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionExpiresIn.Seconds()),
	})

	s.store.RecordAudit(user.Username, "login_success", clientIP)

	writeJSON(w, http.StatusOK, map[string]string{
		"username": user.Username,
		"role":     user.Role,
	})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		s.store.DeleteSession(cookie.Value)
	}

	session := sessionFromContext(r.Context())
	if session != nil {
		s.store.RecordAudit(session.Username, "logout", "")
	}

	clearAuthCookies(w)

	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

func (s *Server) currentUser(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())

	writeJSON(w, http.StatusOK, map[string]string{
		"username": session.Username,
		"role":     session.Role,
	})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())

	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
	}

	if err := readJSON(w, r, &input); err != nil {
		return
	}

	if input.NewPassword != input.ConfirmPassword {
		writeError(w, http.StatusBadRequest, "passwords_do_not_match")
		return
	}

	if err := s.store.ChangePassword(session.Username, input.CurrentPassword, input.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.store.RecordAudit(session.Username, "password_changed", "")
	clearAuthCookies(w)

	writeJSON(w, http.StatusOK, map[string]string{"status": "password_changed"})
}

func (s *Server) getConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"panel_mode":           "authorized_research",
		"data_retention_days":  7,
		"remote_admin_enabled": false,
		"credential_export":    false,
		"session_export":       false,
		"raw_request_logging":  false,
	})
}

func (s *Server) getMetrics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.GetMetrics())
}

func (s *Server) recordResearchEvent(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())

	if session.Role != "admin" && session.Role != "researcher" {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	var input struct {
		CampaignID    string `json:"campaign_id"`
		ControlTested string `json:"control_tested"`
		Outcome       string `json:"outcome"`
	}

	if err := readJSON(w, r, &input); err != nil {
		return
	}

	if input.CampaignID == "" || input.ControlTested == "" || input.Outcome == "" {
		writeError(w, http.StatusBadRequest, "missing_fields")
		return
	}

	s.store.RecordResearchEvent()
	s.store.RecordAudit(
		session.Username,
		"research_event_recorded",
		input.ControlTested+" / "+input.Outcome,
	)

	writeJSON(w, http.StatusCreated, map[string]string{"status": "recorded"})
}

func (s *Server) getAudit(w http.ResponseWriter, r *http.Request) {
	session := sessionFromContext(r.Context())

	if session.Role != "admin" && session.Role != "auditor" {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	writeJSON(w, http.StatusOK, s.store.GetAudit())
}
