package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookieName = "panel_session"
	sessionLifetime   = 8 * time.Hour
	maxLoginAttempts  = 5
	lockoutDuration   = 15 * time.Minute
)

type User struct {
	ID                 int
	Username           string
	PasswordHash       string
	Role               string
	FailedLoginAttempts int
	LockedUntil        time.Time
}

type Session struct {
	ID        int
	UserID    int
	CSRFToken string
	ExpiresAt time.Time
	User      *User
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(hash), err
}

func verifyPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func randomToken() (string, error) {
	raw := make([]byte, 32)

	if _, err := rand.Read(raw); err != nil {
		return "", err
	}

	return hex.EncodeToString(raw), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func validPassword(password string) bool {
	if len(password) < 12 {
		return false
	}

	var hasUpper, hasLower, hasNumber bool

	for _, character := range password {
		switch {
		case unicode.IsUpper(character):
			hasUpper = true
		case unicode.IsLower(character):
			hasLower = true
		case unicode.IsNumber(character):
			hasNumber = true
		}
	}

	return hasUpper && hasLower && hasNumber
}

func (s *Server) requireRole(roles ...string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			session, err := s.currentSession(r)

			if err != nil {
				writeError(w, http.StatusUnauthorized, "authentication_required")
				return
			}

			allowed := false

			for _, role := range roles {
				if session.User.Role == role {
					allowed = true
					break
				}
			}

			if !allowed {
				writeError(w, http.StatusForbidden, "insufficient_permissions")
				return
			}

			next(w, r)
		}
	}
}

func (s *Server) currentSession(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(sessionCookieName)

	if err != nil {
		return nil, err
	}

	session, err := s.store.GetSession(hashToken(cookie.Value))

	if err != nil {
		return nil, err
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		provided := r.Header.Get("X-CSRF-Token")

		if subtle.ConstantTimeCompare(
			[]byte(provided),
			[]byte(session.CSRFToken),
		) != 1 {
			return nil, errors.New("csrf_validation_failed")
		}
	}

	return session, nil
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false, // Set true when serving the panel over HTTPS.
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false,
	})
}

func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}
