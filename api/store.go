package api

import (
	"database/sql"
	"errors"
	"time"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	db *sql.DB
}

func NewStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	if _, err := db.Exec(`
		PRAGMA journal_mode=WAL;
		PRAGMA foreign_keys=ON;

		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL CHECK (role IN ('admin', 'researcher', 'auditor')),
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			last_login_at INTEGER,
			failed_login_attempts INTEGER NOT NULL DEFAULT 0,
			locked_until INTEGER
		);

		CREATE TABLE IF NOT EXISTS sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			token_hash TEXT NOT NULL UNIQUE,
			csrf_token TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS audit_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			actor TEXT NOT NULL,
			action TEXT NOT NULL,
			detail TEXT NOT NULL,
			created_at INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS research_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			campaign_id TEXT NOT NULL,
			control_tested TEXT NOT NULL,
			outcome TEXT NOT NULL,
			created_at INTEGER NOT NULL
		);
	`); err != nil {
		return nil, err
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) CountAdmins() (int, error) {
	var count int

	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM users WHERE role = 'admin'`,
	).Scan(&count)

	return count, err
}

func (s *Store) CreateUser(username, passwordHash, role string) error {
	now := time.Now().Unix()

	_, err := s.db.Exec(
		`INSERT INTO users (username, password_hash, role, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)`,
		username, passwordHash, role, now, now,
	)

	return err
}

func (s *Store) GetUserByUsername(username string) (*User, error) {
	row := s.db.QueryRow(
		`SELECT id, username, password_hash, role, failed_login_attempts, locked_until
		 FROM users WHERE username = ?`,
		username,
	)

	user := &User{}

	var lockedUntil sql.NullInt64

	err := row.Scan(
		&user.ID,
		&user.Username,
		&user.PasswordHash,
		&user.Role,
		&user.FailedLoginAttempts,
		&lockedUntil,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}

	if err != nil {
		return nil, err
	}

	if lockedUntil.Valid {
		user.LockedUntil = time.Unix(lockedUntil.Int64, 0)
	}

	return user, nil
}

func (s *Store) RecordFailedLogin(userID int, lockedUntil time.Time) error {
	now := time.Now().Unix()

	_, err := s.db.Exec(
		`UPDATE users
		 SET failed_login_attempts = failed_login_attempts + 1,
		     locked_until = ?
		 WHERE id = ?`,
		lockedUntil.Unix(), userID,
	)

	return err
}

func (s *Store) RecordSuccessfulLogin(userID int) error {
	now := time.Now().Unix()

	_, err := s.db.Exec(
		`UPDATE users
		 SET failed_login_attempts = 0,
		     locked_until = NULL,
		     last_login_at = ?
		 WHERE id = ?`,
		now, userID,
	)

	return err
}

func (s *Store) CreateSession(userID int, tokenHash, csrfToken string, expiresAt time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO sessions (user_id, token_hash, csrf_token, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		userID, tokenHash, csrfToken, time.Now().Unix(), expiresAt.Unix(),
	)

	return err
}

func (s *Store) GetSession(tokenHash string) (*Session, error) {
	row := s.db.QueryRow(
		`SELECT s.id, s.user_id, s.csrf_token, s.expires_at, u.username, u.role
		 FROM sessions s
		 JOIN users u ON u.id = s.user_id
		 WHERE s.token_hash = ? AND s.expires_at > ?`,
		tokenHash, time.Now().Unix(),
	)

	session := &Session{}
	user := &User{}

	err := row.Scan(
		&session.ID,
		&session.UserID,
		&session.CSRFToken,
		&session.ExpiresAt,
		&user.Username,
		&user.Role,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}

	if err != nil {
		return nil, err
	}

	session.User = user

	return session, nil
}

func (s *Store) DeleteSession(tokenHash string) error {
	_, err := s.db.Exec(
		`DELETE FROM sessions WHERE token_hash = ?`,
		tokenHash,
	)

	return err
}

func (s *Store) DeleteSessionsForUser(userID int) error {
	_, err := s.db.Exec(
		`DELETE FROM sessions WHERE user_id = ?`,
		userID,
	)

	return err
}

func (s *Store) UpdatePassword(userID int, passwordHash string) error {
	_, err := s.db.Exec(
		`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`,
		passwordHash, time.Now().Unix(), userID,
	)

	return err
}

func (s *Store) RecordAudit(actor, action, detail string) error {
	_, err := s.db.Exec(
		`INSERT INTO audit_events (actor, action, detail, created_at)
		 VALUES (?, ?, ?, ?)`,
		actor, action, detail, time.Now().Unix(),
	)

	return err
}

func (s *Store) ListAudit(limit int) ([]AuditEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	rows, err := s.db.Query(
		`SELECT id, actor, action, detail, created_at
		 FROM audit_events
		 ORDER BY id DESC
		 LIMIT ?`,
		limit,
	)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	events := []AuditEvent{}

	for rows.Next() {
		var event AuditEvent
		var createdAt int64

		if err := rows.Scan(
			&event.ID,
			&event.Actor,
			&event.Action,
			&event.Detail,
			&createdAt,
		); err != nil {
			return nil, err
		}

		event.CreatedAt = time.Unix(createdAt, 0)
		events = append(events, event)
	}

	return events, rows.Err()
}

func (s *Store) RecordResearchEvent(campaignID, control, outcome string) error {
	_, err := s.db.Exec(
		`INSERT INTO research_events (campaign_id, control_tested, outcome, created_at)
		 VALUES (?, ?, ?, ?)`,
		campaignID, control, outcome, time.Now().Unix(),
	)

	return err
}

func (s *Store) GetMetrics() (map[string]any, error) {
	var researchEvents, blocked, detected int

	err := s.db.QueryRow(
		`SELECT COUNT(*),
		        COALESCE(SUM(CASE WHEN outcome = 'blocked' THEN 1 ELSE 0 END), 0),
		        COALESCE(SUM(CASE WHEN outcome = 'detected' THEN 1 ELSE 0 END), 0)
		 FROM research_events`,
	).Scan(&researchEvents, &blocked, &detected)

	if err != nil {
		return nil, err
	}

	return map[string]any{
		"research_events":   researchEvents,
		"controls_blocked":  blocked,
		"controls_detected": detected,
	}, nil
}
