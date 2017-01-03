// Copyright 2016 The Gem Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

/*
Package authmidware provides HTTP Basic and HTTP Digest authentication for Gem Web framework.

This package depends on go-http-auth, more usages may be obtained on
https://github.com/abbot/go-http-auth.

Example

	package main

	import (
		"github.com/abbot/go-http-auth"
		"github.com/go-gem/gem"
		"github.com/go-gem/middleware-auth"
	)

	var (
		salt     = []byte("salt")
		magic    = []byte("$1$")
		username = "foo"
		password = []byte("bar")
	)

	// basic auth middleware
	var (
		basicPasswd = string(auth.MD5Crypt(password, salt, magic))

		basicAuthenticator = auth.NewBasicAuthenticator("", func(user, realm string) string {
			if user == username {
				return basicPasswd
			}
			return ""
		})

		basicAuth = authmidware.New(basicAuthenticator)
	)

	func basicHandle(ctx *gem.Context) {
		ctx.HTML(200, "hello "+basicAuth.Username(ctx))
	}

	// digest auth middleware
	var (
		digestAuthenticator = auth.NewDigestAuthenticator("", func(user, realm string) string {
			if user == "foo" {
				// MD5(username:realm:password)
				return "e0a109b991367f513dfa73bbae05fb07"
			}
			return ""
		})

		digestAuth = authmidware.New(digestAuthenticator)
	)

	func digestHandle(ctx *gem.Context) {
		ctx.HTML(200, "hello "+digestAuth.Username(ctx))
	}

	func main() {
		router := gem.NewRouter()

		// basic auth
		router.GET("/basic", basicHandle, &gem.HandlerOption{
			Middlewares: []gem.Middleware{basicAuth},
		})

		// digest auth
		router.GET("/digest", digestHandle, &gem.HandlerOption{
			Middlewares: []gem.Middleware{digestAuth},
		})

		gem.ListenAndServe(":8080", router.Handler())
	}
*/
package authmidware

import (
	"net/http"

	"github.com/abbot/go-http-auth"
	"github.com/go-gem/gem"
)

const authContextKey = "gem.auth.name"

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
