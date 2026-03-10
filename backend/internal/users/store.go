package users

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// User is a proxy user with auth credentials and group memberships.
type User struct {
	ID           string   `json:"id"`
	Username     string   `json:"username"`
	PasswordHash string   `json:"password_hash,omitempty"` // bcrypt, never returned by API
	Token        string   `json:"token"`                   // plaintext API/proxy token (v2ray password)
	VMessUUID    string   `json:"vmess_uuid"`              // UUID for VMess inbound
	Groups       []string `json:"groups"`                  // group IDs
	Enabled      bool     `json:"enabled"`
	Note         string   `json:"note,omitempty"`
	CreatedAt    string   `json:"created_at"`
}

// Group defines URL patterns allowed for proxy access.
type Group struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	AllowedPatterns []string `json:"allowed_patterns"` // JS-compatible regex patterns
	Description     string   `json:"description,omitempty"`
}

// V2RayAccount is the view of a user that the proxy manager needs.
type V2RayAccount struct {
	Username  string
	Token     string   // plaintext proxy password (= user.Token)
	VMessUUID string
	Patterns  []string // nil = allow all; non-nil = restrict to these regex patterns
}

type storeData struct {
	Users  []User  `json:"users"`
	Groups []Group `json:"groups"`
}

// Store manages users and groups with JSON persistence.
type Store struct {
	mu       sync.RWMutex
	users    []User
	groups   []Group
	filePath string
}

// NewStore loads (or initialises) a Store from filePath.
// Pass filePath="" for an in-memory-only store (no persistence).
func NewStore(filePath string) (*Store, error) {
	s := &Store{filePath: filePath, users: []User{}, groups: []Group{}}
	if filePath == "" {
		return s, nil // in-memory only
	}
	return s, s.load()
}

func (s *Store) load() error {
	if s.filePath == "" {
		return nil
	}
	b, err := os.ReadFile(s.filePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var d storeData
	if err := json.Unmarshal(b, &d); err != nil {
		return err
	}
	s.mu.Lock()
	s.users = d.Users
	s.groups = d.Groups
	s.mu.Unlock()
	return nil
}

func (s *Store) save() error {
	if s.filePath == "" {
		return nil // in-memory only
	}
	b, err := json.MarshalIndent(storeData{Users: s.users, Groups: s.groups}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.filePath, b, 0600)
}

// ─── Users ───────────────────────────────────────────────────────────────────

// ListUsers returns all users with PasswordHash stripped.
func (s *Store) ListUsers() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, len(s.users))
	copy(out, s.users)
	for i := range out {
		out[i].PasswordHash = ""
	}
	return out
}

// GetUser returns a single user by ID (no password hash).
func (s *Store) GetUser(id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.ID == id {
			cp := u
			cp.PasswordHash = ""
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("user %q not found", id)
}

// CreateUser adds a new user. Password is hashed; token and VMess UUID are generated.
func (s *Store) CreateUser(username, password string, groups []string, note string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, u := range s.users {
		if u.Username == username {
			return nil, fmt.Errorf("user %q already exists", username)
		}
	}
	u := User{
		ID:        uuid.New().String(),
		Username:  username,
		VMessUUID: uuid.New().String(),
		Token:     newToken(),
		Groups:    groups,
		Enabled:   true,
		Note:      note,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if password != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("hash password: %w", err)
		}
		u.PasswordHash = string(h)
	}
	s.users = append(s.users, u)
	if err := s.save(); err != nil {
		return nil, err
	}
	cp := u
	cp.PasswordHash = ""
	return &cp, nil
}

// UpdateUser applies a partial update to a user by ID.
func (s *Store) UpdateUser(id, password string, groups []string, enabled bool, note string, regenToken bool) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, u := range s.users {
		if u.ID != id {
			continue
		}
		s.users[i].Note = note
		s.users[i].Groups = groups
		s.users[i].Enabled = enabled
		if password != "" {
			h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				return nil, fmt.Errorf("hash password: %w", err)
			}
			s.users[i].PasswordHash = string(h)
		}
		if regenToken {
			s.users[i].Token = newToken()
		}
		if err := s.save(); err != nil {
			return nil, err
		}
		cp := s.users[i]
		cp.PasswordHash = ""
		return &cp, nil
	}
	return nil, fmt.Errorf("user %q not found", id)
}

// DeleteUser removes a user by ID.
func (s *Store) DeleteUser(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, u := range s.users {
		if u.ID == id {
			s.users = append(s.users[:i], s.users[i+1:]...)
			return s.save()
		}
	}
	return fmt.Errorf("user %q not found", id)
}

// ValidateAuth checks username + secret (token or password). Returns user on match.
func (s *Store) ValidateAuth(username, secret string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if !u.Enabled || u.Username != username {
			continue
		}
		if u.Token == secret {
			cp := u
			cp.PasswordHash = ""
			return &cp, true
		}
		if u.PasswordHash != "" {
			if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(secret)) == nil {
				cp := u
				cp.PasswordHash = ""
				return &cp, true
			}
		}
	}
	return nil, false
}

// ─── Groups ───────────────────────────────────────────────────────────────────

func (s *Store) ListGroups() []Group {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Group, len(s.groups))
	copy(out, s.groups)
	return out
}

func (s *Store) CreateGroup(name string, patterns []string, description string) (*Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.groups {
		if g.Name == name {
			return nil, fmt.Errorf("group %q already exists", name)
		}
	}
	g := Group{
		ID:              uuid.New().String(),
		Name:            name,
		AllowedPatterns: patterns,
		Description:     description,
	}
	s.groups = append(s.groups, g)
	if err := s.save(); err != nil {
		return nil, err
	}
	return &g, nil
}

func (s *Store) UpdateGroup(id, name string, patterns []string, description string) (*Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, g := range s.groups {
		if g.ID != id {
			continue
		}
		s.groups[i].Name = name
		s.groups[i].AllowedPatterns = patterns
		s.groups[i].Description = description
		if err := s.save(); err != nil {
			return nil, err
		}
		cp := s.groups[i]
		return &cp, nil
	}
	return nil, fmt.Errorf("group %q not found", id)
}

func (s *Store) DeleteGroup(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, g := range s.groups {
		if g.ID == id {
			s.groups = append(s.groups[:i], s.groups[i+1:]...)
			return s.save()
		}
	}
	return fmt.Errorf("group %q not found", id)
}

// ─── v2ray bridge ─────────────────────────────────────────────────────────────

// AccountsForV2Ray returns enabled users as V2RayAccounts.
// Patterns = union of all group patterns for that user; nil = no restriction.
func (s *Store) AccountsForV2Ray() []V2RayAccount {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.users) == 0 {
		return nil
	}

	// build group → patterns map
	gmap := make(map[string][]string, len(s.groups))
	for _, g := range s.groups {
		gmap[g.ID] = g.AllowedPatterns
	}

	out := make([]V2RayAccount, 0, len(s.users))
	for _, u := range s.users {
		if !u.Enabled {
			continue
		}
		var patterns []string
		if len(u.Groups) > 0 {
			seen := make(map[string]bool)
			for _, gid := range u.Groups {
				for _, p := range gmap[gid] {
					if !seen[p] {
						seen[p] = true
						patterns = append(patterns, p)
					}
				}
			}
		}
		out = append(out, V2RayAccount{
			Username:  u.Username,
			Token:     u.Token,
			VMessUUID: u.VMessUUID,
			Patterns:  patterns, // nil = allow all
		})
	}
	return out
}

// GetUserPatterns returns the combined URL patterns for a user (by username).
// Returns nil if user has no groups (= allow all).
func (s *Store) GetUserPatterns(username string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var found *User
	for i := range s.users {
		if s.users[i].Username == username {
			found = &s.users[i]
			break
		}
	}
	if found == nil || len(found.Groups) == 0 {
		return nil
	}
	gmap := make(map[string][]string, len(s.groups))
	for _, g := range s.groups {
		gmap[g.ID] = g.AllowedPatterns
	}
	seen := make(map[string]bool)
	var patterns []string
	for _, gid := range found.Groups {
		for _, p := range gmap[gid] {
			if !seen[p] {
				seen[p] = true
				patterns = append(patterns, p)
			}
		}
	}
	return patterns
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func newToken() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
