// Copyright 2016 The Gem Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

/*
Package authmidware provides HTTP Basic and HTTP Digest authentication for Gem Web framework.

This package depends on go-http-auth, more usages may be obtained on
https://github.com/abbot/go-http-auth.

Example: see https://github.com/go-gem/examples/tree/master/auth.
*/
package authmidware

import (
	"net/http"

	"github.com/abbot/go-http-auth"
	"github.com/go-gem/gem"
)

const authContextKey = "auth_name"

// New returns an Auth middleware with the given authenticator.
func New(authenticator Authenticator) *Auth {
	return &Auth{
		authenticator: authenticator,

		// Context key for storing username.
		ContextKey: authContextKey,
	}
}

// Authenticator interface.
type Authenticator interface {
	Wrap(wrapped auth.AuthenticatedHandlerFunc) http.HandlerFunc
}

// Auth middleware.
type Auth struct {
	authenticator Authenticator
	ContextKey    string
}

// Wrap implements the middleware interface.
func (a *Auth) Wrap(next gem.Handler) gem.Handler {
	return gem.HandlerFunc(func(ctx *gem.Context) {
		a.authenticator.Wrap(func(w http.ResponseWriter, r *auth.AuthenticatedRequest) {
			ctx.SetUserValue(a.ContextKey, r.Username)
			next.Handle(ctx)
		})(ctx.Response, ctx.Request)
	})
}

// Username returns the username.
//
// Returns empty string if it does not exist
// or not a valid name.
func (m *Auth) Username(ctx *gem.Context) string {
	if name, ok := ctx.UserValue(m.ContextKey).(string); ok {
		return name
	}

	return ""
}
