package clients

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"azugo.io/core/http"
)

// methodName is the shape of one sign-in method's name, as the sign-in start takes it:
// anything else in the discovery document is not passed on to the page.
var methodName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,63}$`)

// SignInMethods reads which ways of signing in the Auth Service offers, from its
// public discovery document: `acr_values_supported` names each one by its login
// method (eparakstsMobile, eidScan, webEid, legacyEid, …), in its own order. The
// answer belongs to the deployment, so no identity is presented.
type SignInMethods struct {
	client http.Client
	url    string
}

// NewSignInMethods reads the discovery document of the Auth Service at baseURL.
func NewSignInMethods(c http.Client, baseURL string) *SignInMethods {
	return &SignInMethods{client: c, url: strings.TrimRight(baseURL, "/") + "/.well-known/openid-configuration"}
}

// Flows returns the sign-in methods the Auth Service offers. It is named for
// FlowSource, so OfferedFlows can remember the answer the same way.
func (s *SignInMethods) Flows(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, offerCallTimeout)
	defer cancel()

	var doc struct {
		Methods []string `json:"acr_values_supported"`
	}
	if err := s.client.WithContext(ctx).GetJSON(s.url, &doc); err != nil {
		return nil, fmt.Errorf("auth: discovery: %w", err)
	}
	methods := make([]string, 0, len(doc.Methods))
	for _, m := range doc.Methods {
		if m = strings.TrimSpace(m); methodName.MatchString(m) {
			methods = append(methods, m)
		}
	}

	return methods, nil
}
