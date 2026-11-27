package api

import (
	"crypto/subtle"
	"net/http"
	"os"
)

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		expected := "Bearer " + os.Getenv("PANEL_ADMIN_TOKEN")

		provided := r.Header.Get("Authorization")

		if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		next(w, r)
	}
}
