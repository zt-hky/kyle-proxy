package auth

import (
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const sessionCookie = "kyle_session"

// Claims holds the JWT payload for the management UI session.
type Claims struct {
	Login string `json:"login"` // GitHub username or "admin"
	jwt.RegisteredClaims
}

func jwtSecret() []byte {
	if s := os.Getenv("AUTH_SECRET"); s != "" {
		return []byte(s)
	}
	return []byte("kyle-proxy-dev-secret-change-me")
}

// IssueSession sets a signed JWT cookie on the response.
func IssueSession(w http.ResponseWriter, login string, ttl time.Duration) error {
	claims := Claims{
		Login: login,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret())
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl / time.Second),
	})
	return nil
}

// ValidateSession parses and validates the JWT from the request cookie.
func ValidateSession(r *http.Request) (*Claims, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, false
	}
	tok, err := jwt.ParseWithClaims(c.Value, &Claims{}, func(_ *jwt.Token) (interface{}, error) {
		return jwtSecret(), nil
	})
	if err != nil || !tok.Valid {
		return nil, false
	}
	claims, ok := tok.Claims.(*Claims)
	return claims, ok
}

// ClearSession deletes the session cookie.
func ClearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
}
