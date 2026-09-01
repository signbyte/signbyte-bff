package asclient

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/go-quicktest/qt"
)

// jwtWith builds a token whose (unverified) payload carries the given claims, so
// the claim-reading helpers can be exercised without a real signer.
func jwtWith(claims map[string]any) string {
	payload, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc(payload) + ".sig"
}

func TestLoginBindingFromToken(t *testing.T) {
	// The same person via two methods → two distinct bindings, so the on-behalf
	// token cache (keyed on the stable subject) does not cross login methods.
	web := LoginBindingFromToken(jwtWith(map[string]any{"sub": "u1", "login_method": "webEid", "loa": "high"}))
	scan := LoginBindingFromToken(jwtWith(map[string]any{"sub": "u1", "login_method": "eidScan", "loa": "high"}))
	qt.Check(t, qt.Equals(web, "lm:webEid|loa:high"))
	qt.Check(t, qt.Equals(scan, "lm:eidScan|loa:high"))
	qt.Check(t, qt.IsTrue(web != scan))

	// No binding claims, or an unreadable token → empty (subject-only cache keying).
	qt.Check(t, qt.Equals(LoginBindingFromToken(jwtWith(map[string]any{"sub": "u1"})), ""))
	qt.Check(t, qt.Equals(LoginBindingFromToken("not-a-jwt"), ""))
}
