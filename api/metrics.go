package api

import (
	"net/http"
)

var allowedControls = map[string]bool{
	"email_gateway":      true,
	"conditional_access": true,
	"passkey":            true,
	"user_reporting":     true,
}

var allowedOutcomes = map[string]bool{
	"blocked":       true,
	"detected":      true,
	"not_detected":  true,
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics, err := s.store.GetMetrics()

	if err != nil {
		writeError(w, http.StatusInternalServerError, "metrics_unavailable")
		return
	}

	writeJSON(w, http.StatusOK, metrics)
}

func (s *Server) handleResearchEvent(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CampaignID    string `json:"campaign_id"`
		ControlTested string `json:"control_tested"`
		Outcome       string `json:"outcome"`
	}

	if err := decodeJSON(w, r, &input); err != nil {
		return
	}

	if input.CampaignID == "" ||
		!allowedControls[input.ControlTested] ||
		!allowedOutcomes[input.Outcome] {
		writeError(w, http.StatusBadRequest, "invalid_research_event")
		return
	}

	if err := s.store.RecordResearchEvent(
		input.CampaignID,
		input.ControlTested,
		input.Outcome,
	); err != nil {
		writeError(w, http.StatusInternalServerError, "record_failed")
		return
	}

	session, _ := s.currentSession(r)
	_ = s.store.RecordAudit(
		session.User.Username,
		"research_event_recorded",
		input.ControlTested+" / "+input.Outcome,
	)

	writeJSON(w, http.StatusCreated, map[string]string{"status": "recorded"})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	events, err := s.store.ListAudit(100)

	if err != nil {
		writeError(w, http.StatusInternalServerError, "audit_unavailable")
		return
	}

	writeJSON(w, http.StatusOK, events)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"panel_mode":           "authorized_research",
		"data_retention_days":  7,
		"remote_admin_enabled": false,
		"credential_export":    false,
		"session_export":       false,
		"raw_request_logging":  false,
	})
}
