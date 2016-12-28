// Copyright 2016 The Gem Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

package authmidware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/abbot/go-http-auth"
	"github.com/go-gem/gem"
)

var (
	salt         = []byte("salt")
	magic        = []byte("$1$")
	username     = "foo"
	password     = []byte("bar")
	encryptedPsw = string(auth.MD5Crypt(password, salt, magic))

	authenticator = auth.NewBasicAuthenticator("", func(user, realm string) string {
		if user == username {
			return encryptedPsw
		}
		return ""
	})

	authMidware = New(authenticator)
)

func TestAuth(t *testing.T) {
	var pass bool
	handler := authMidware.Wrap(gem.HandlerFunc(func(ctx *gem.Context) {
		pass = true
	}))

	req, err := http.NewRequest("GET", "", nil)
	if err != nil {
		t.Fatalf("failed to create request: %q", err)
	}

	resp := httptest.NewRecorder()

	ctx := &gem.Context{Request: req, Response: resp}

	// invalid authorization.
	handler.Handle(ctx)
	if pass {
		t.Error("unexpected result")
	}

	// valid authorization.
	req.Header.Add("Authorization", `Basic Zm9vOmJhcg==`)
	handler.Handle(ctx)
	if !pass {
		t.Error("failed to pass the handler")
	}

	// check username
	if name := authMidware.Username(ctx); username != name {
		t.Errorf("expected username %q, got %q", username, name)
	}
}

func TestAuth_Username(t *testing.T) {
	ctx := &gem.Context{
		Request:  httptest.NewRequest("GET", "/", nil),
		Response: httptest.NewRecorder(),
	}

	want := ""
	if name := authMidware.Username(ctx); want != name {
		t.Errorf("expected name %q, got %q", want, name)
	}

	// invalid name.
	ctx.SetUserValue(authMidware.ContextKey, true)
	if name := authMidware.Username(ctx); want != name {
		t.Errorf("expected name %q, got %q", want, name)
	}

	want = "bar"
	ctx.SetUserValue(authMidware.ContextKey, want)
	if name := authMidware.Username(ctx); want != name {
		t.Errorf("expected name %q, got %q", want, name)
	}
}
