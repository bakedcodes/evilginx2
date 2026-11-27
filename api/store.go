package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const sessionExpiresIn = 8 * time.Hour

var (
	ErrInvalidCredentials = errors.New("invalid_username_or_password")
	ErrAccountLocked      = errors.New("account_temporarily_locked")
	ErrUserExists         = errors.New("username_already_exists")
	ErrUserNotFound       = errors.New("user_not_found")
	ErrWeakPassword       = errors.New("password_must_be_at_least_12_characters")
	ErrInvalidUsername    = errors.New("invalid_username")
	ErrInvalidRole        = errors.New("invalid_role")
)

type User struct {
	Username            string    `json:"username"`
	PasswordHash        string    `json:"password_hash"`
	Role                string    `json:"role"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
	LastLoginAt         time.Time `json:"last_login_at,omitempty"`
	FailedLoginAttempts int       `json:"failed_login_attempts"`
	LockedUntil         time.Time `json:"locked_until,omitempty"`
}

type Session struct {
	Token     string
	TokenHash string
	Username  string
	Role      string
	CSRFToken string
	ExpiresAt time.Time
}

type AuditEvent struct {
	ID        int       `json:"id"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Detail    string    `json:"detail"`
	CreatedAt time.Time `json:"created_at"`
}

type Metrics struct {
	ResearchEvents      int       `json:"research_events"`
	AuthenticationTests int       `json:"authentication_tests"`
	MfaPrompts          int       `json:"mfa_prompts"`
	ControlsTriggered   int       `json:"controls_triggered"`
	LastEventAt         time.Time `json:"last_event_at,omitempty"`
}

type Store struct {
	mu         sync.RWMutex
	usersPath  string
	users      map[string]*User
	sessions   map[string]*Session
	loginTries map[string][]time.Time
	audit      []AuditEvent
	metrics    Metrics
}

func NewStore(usersPath string) (*Store, error) {
	store := &Store{
		usersPath:  usersPath,
		users:      make(map[string]*User),
		sessions:   make(map[string]*Session),
		loginTries: make(map[string][]time.Time),
	}

	if err := store.loadUsers(); err != nil {
		return nil, err
	}

	return store, nil
}

func (s *Store) loadUsers() error {
	data, err := os.ReadFile(s.usersPath)

	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	if err != nil {
		return err
	}

	users := make(map[string]*User)

	if err := json.Unmarshal(data, &users); err != nil {
		return err
	}

	s.users = users
	return nil
}

func (s *Store) saveUsers() error {
	data, err := json.MarshalIndent(s.users, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(s.usersPath), 0700); err != nil {
		return err
	}

	tempPath := s.usersPath + ".tmp"

	if err := os.WriteFile(tempPath, data, 0600); err != nil {
		return err
	}

	return os.Rename(tempPath, s.usersPath)
}

func (s *Store) HasUsers() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.users) > 0
}

func (s *Store) CreateUser(username, password, role string) error {
	username = normalizeUsername(username)

	if !validUsername(username) {
		return ErrInvalidUsername
	}

	if !strongPassword(password) {
		return ErrWeakPassword
	}

	if role != "admin" && role != "researcher" && role != "auditor" {
		return ErrInvalidRole
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[username]; exists {
		return ErrUserExists
	}

	now := time.Now().UTC()

	s.users[username] = &User{
		Username:     username,
		PasswordHash: string(passwordHash),
		Role:         role,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	return s.saveUsers()
}

func (s *Store) Authenticate(username, password, clientIP string) (*User, error) {
	username = normalizeUsername(username)

	s.mu.Lock()
	defer s.mu.Unlock()

	if isRateLimited(s.loginTries[clientIP]) {
		return nil, ErrAccountLocked
	}

	user, exists := s.users[username]
	if !exists {
		s.loginTries[clientIP] = append(s.loginTries[clientIP], time.Now().UTC())
		return nil, ErrInvalidCredentials
	}

	if time.Now().Before(user.LockedUntil) {
		return nil, ErrAccountLocked
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		user.FailedLoginAttempts++
		s.loginTries[clientIP] = append(s.loginTries[clientIP], time.Now().UTC())

		if user.FailedLoginAttempts >= 5 {
			user.LockedUntil = time.Now().UTC().Add(15 * time.Minute)
		}

		_ = s.saveUsers()

		return nil, ErrInvalidCredentials
	}

	user.FailedLoginAttempts = 0
	user.LockedUntil = time.Time{}
	user.LastLoginAt = time.Now().UTC()

	_ = s.saveUsers()

	return user, nil
}

func (s *Store) CreateSession(user *User) (*Session, error) {
	token, err := randomToken(32)
	if err != nil {
		return nil, err
	}

	csrfToken, err := randomToken(32)
	if err != nil {
		return nil, err
	}

	session := &Session{
		Token:     token,
		TokenHash: hashToken(token),
		Username:  user.Username,
		Role:      user.Role,
		CSRFToken: csrfToken,
		ExpiresAt: time.Now().UTC().Add(sessionExpiresIn),
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[session.TokenHash] = session

	return session, nil
}

func (s *Store) GetSession(token string) (*Session, bool) {
	if token == "" {
		return nil, false
	}

	tokenHash := hashToken(token)

	s.mu.RLock()
	defer s.mu.RUnlock()

	session, exists := s.sessions[tokenHash]
	if !exists || time.Now().After(session.ExpiresAt) {
		return nil, false
	}

	return session, true
}

func (s *Store) DeleteSession(token string) {
	if token == "" {
		return
	}

	tokenHash := hashToken(token)

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, tokenHash)
}

func (s *Store) ChangePassword(username, currentPassword, newPassword string) error {
	username = normalizeUsername(username)

	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[username]
	if !exists {
		return ErrUserNotFound
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(currentPassword)); err != nil {
		return ErrInvalidCredentials
	}

	if !strongPassword(newPassword) {
		return ErrWeakPassword
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user.PasswordHash = string(passwordHash)
	user.UpdatedAt = time.Now().UTC()

	for tokenHash, session := range s.sessions {
		if session.Username == username {
			delete(s.sessions, tokenHash)
		}
	}

	return s.saveUsers()
}

func (s *Store) RecordAudit(actor, action, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.audit = append(s.audit, AuditEvent{
		ID:        len(s.audit) + 1,
		Actor:     actor,
		Action:    action,
		Detail:    detail,
		CreatedAt: time.Now().UTC(),
	})
}

func (s *Store) GetAudit() []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]AuditEvent, len(s.audit))
	copy(result, s.audit)

	return result
}

func (s *Store) RecordResearchEvent() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.metrics.ResearchEvents++
	s.metrics.LastEventAt = time.Now().UTC()
}

func (s *Store) GetMetrics() Metrics {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.metrics
}

func normalizeUsername(username string) string {
	if len(username) > 64 {
		username = username[:64]
	}

	return username
}

func validUsername(username string) bool {
	if len(username) < 3 || len(username) > 64 {
		return false
	}

	for _, character := range username {
		valid := (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '.' ||
			character == '_' ||
			character == '-'

		if !valid {
			return false
		}
	}

	return true
}

func strongPassword(password string) bool {
	return len(password) >= 12
}

func isRateLimited(attempts []time.Time) bool {
	now := time.Now().UTC()
	recentAttempts := 0

	for _, attempt := range attempts {
		if now.Sub(attempt) < 15*time.Minute {
			recentAttempts++
		}
	}

	return recentAttempts >= 10
}

func randomToken(length int) (string, error) {
	bytes := make([]byte, length)

	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func readJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
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
