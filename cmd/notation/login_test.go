package main

import "testing"

const (
	validUsername      = "username"
	validPassword      = "password"
	validIdentityToken = "identity"
)

func TestLogin_newCredentialFromInput(t *testing.T) {
	// username/password
	c := newCredentialFromInput(validUsername, validPassword)
	if c.Username != validUsername || c.Password != validPassword {
		t.Fatalf("expected %s, %s, got %s, %s",
			validUsername,
			validPassword,
			c.Username,
			c.Password,
		)
	}

	// token
	c = newCredentialFromInput("", validIdentityToken)
	if c.RefreshToken != validIdentityToken {
		t.Fatalf("expected %s, got %s", validIdentityToken, c.RefreshToken)
	}
}
