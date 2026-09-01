// Package response holds the Portal-API response body structs.
package response

// LoginStart is returned to the app to begin a login: the URL to send the browser
// to, plus the opaque state the app may correlate.
type LoginStart struct {
	AuthorizeURL string `json:"authorize_url"`
	State        string `json:"state"`
}

// Me is the logged-in user's identity, shaped for the app's flow chooser and
// step-up prompts.
type Me struct {
	Sub            string   `json:"sub"`
	Name           string   `json:"name"`
	LoA            string   `json:"loa"`
	LoginMethod    string   `json:"login_method"`
	PermittedFlows []string `json:"permitted_flows"`
	// CanEseal reports whether the person verifiably can e-seal (they hold at
	// least one seal). Absent (null) when seal availability is unknown — the
	// login path did not read the catalog — which is different from false
	// (catalog read, no seals: hide the e-seal action).
	CanEseal *bool `json:"can_eseal,omitempty"`
	// Seals lists the person's seals for the picker (id + display label only —
	// certificates never reach the browser). Present only when CanEseal is.
	Seals []MeSeal `json:"seals,omitempty"`
}

// MeSeal is one seal offered to the seal picker.
type MeSeal struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// WebEIDChallenge is returned to begin an eID-card login: the card challenge the
// app signs in the browser, plus the flow handle to complete with.
type WebEIDChallenge struct {
	Nonce string `json:"nonce"`
	State string `json:"state"`
}

// OK is a minimal success acknowledgement.
type OK struct {
	OK bool `json:"ok"`
}

// Logout acknowledges a logout. LogoutURL, when set, is a front-channel URL the
// browser must navigate to so the Auth Service can clear the federated IdP SSO
// cookie before landing on the app login screen; empty for a non-federated login,
// where the app navigates to its login screen directly.
type Logout struct {
	OK        bool   `json:"ok"`
	LogoutURL string `json:"logoutUrl,omitempty"`
}
