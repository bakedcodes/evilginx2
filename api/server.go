package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

type Metrics struct {
	mu                    sync.Mutex
	CampaignsActive       int       `json:"campaigns_active"`
	AuthenticationTests   int       `json:"authentication_tests"`
	MfaPrompts            int       `json:"mfa_prompts"`
	ControlsTriggered     int       `json:"controls_triggered"`
	ResearchEvents        int       `json:"research_events"`
	LastResearchEventAt   time.Time `json:"last_research_event_at"`
}

type Server struct {
	httpServer *http.Server
	metrics    *Metrics
	audit      []AuditEvent
	auditMu    sync.Mutex
}

type AuditEvent struct {
	ID        int       `json:"id"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Detail    string    `json:"detail"`
	CreatedAt time.Time `json:"created_at"`
}

func NewServer(addr string) *Server {
	metrics := &Metrics{}

	s := &Server{
		metrics: metrics,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", s.handleHealth)
	mux.Handle("GET /metrics", s.requireAdmin(s.handleMetrics))
	mux.Handle("POST /metrics/research-event", s.requireAdmin(s.handleResearchEvent))
	mux.Handle("GET /config", s.requireAdmin(s.handleGetConfig))
	mux.Handle("GET /audit", s.requireAdmin(s.handleAudit))
	mux.Handle("/", s.requireAdmin(http.FileServer(http.Dir("./web"))))

	s.httpServer = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return s
}

func (s *Server) Start() error {
	log.Printf("Research control panel listening on %s", s.httpServer.Addr)
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "evilginx-research-control-panel",
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()

	writeJSON(w, http.StatusOK, s.metrics)
}

func (s *Server) handleResearchEvent(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CampaignID    string `json:"campaign_id"`
		ControlTested string `json:"control_tested"`
		Outcome       string `json:"outcome"`
	}

	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}

	if input.CampaignID == "" || input.ControlTested == "" || input.Outcome == "" {
		writeError(w, http.StatusBadRequest, "campaign_id, control_tested, and outcome are required")
		return
	}

	s.metrics.mu.Lock()
	s.metrics.ResearchEvents++
	s.metrics.LastResearchEventAt = time.Now().UTC()
	s.metrics.mu.Unlock()

	s.recordAudit("researcher", "research_event_recorded", input.ControlTested+" / "+input.Outcome)

	writeJSON(w, http.StatusCreated, map[string]string{"status": "recorded"})
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"panel_mode":            "authorized_research",
		"data_retention_days":   7,
		"remote_admin_enabled":  false,
		"credential_export":     false,
		"session_export":        false,
		"raw_request_logging":   false,
	})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()

	writeJSON(w, http.StatusOK, s.audit)
}

func (s *Server) recordAudit(actor, action, detail string) {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()

	s.audit = append(s.audit, AuditEvent{
		ID:        len(s.audit) + 1,
		Actor:     actor,
		Action:    action,
		Detail:    detail,
		CreatedAt: time.Now().UTC(),
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}
