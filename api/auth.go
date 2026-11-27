package api

import (
	"net/http"
	"strings"
)

const (
	sessionCookieName = "panel_session"
	csrfCookieName    = "panel_csrf"
)

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || cookie.Value == "" {
			writeError(w, http.StatusUnauthorized, "authentication_required")
			return
		}

		session, valid := s.store.GetSession(cookie.Value)
		if !valid {
			clearAuthCookies(w)
			writeError(w, http.StatusUnauthorized, "session_expired")
			return
		}

		if r.Method == http.MethodPost ||
			r.Method == http.MethodPut ||
			r.Method == http.MethodPatch ||
			r.Method == http.MethodDelete {

			csrfCookie, err := r.Cookie(csrfCookieName)
			csrfHeader := r.Header.Get("X-CSRF-Token")

			if err != nil ||
				csrfCookie.Value == "" ||
				csrfHeader == "" ||
				!constantTimeEqual(csrfCookie.Value, csrfHeader) {
				writeError(w, http.StatusForbidden, "invalid_csrf_token")
				return
			}
		}

		r = r.WithContext(withSession(r.Context(), session))
		next.ServeHTTP(w, r)
	}
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}

	return result == 0
}

func clearAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func clientIP(r *http.Request) string {
	ip := r.RemoteAddr

	if index := strings.LastIndex(ip, ":"); index != -1 {
		ip = ip[:index]
	}

	return ip
}
