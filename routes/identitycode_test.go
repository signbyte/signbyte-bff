package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	api "github.com/signbyte/signbyte-bff"
	"github.com/signbyte/signbyte-bff/clients"
	"github.com/signbyte/signbyte-bff/session"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// testIDCodeLV returns a Latvian personal identity code in the one spelling the
// platform stores and compares; testIDCodeLVAsWritten returns the SAME person's
// code the way a Latvian person and a Latvian certificate write it. Both are
// assembled at run time — an identifier-shaped constant in source is
// indistinguishable from a credential to a secret scanner, and from a real
// person's code to a reader.
func testIDCodeLV(digit int) string {
	return "PNOLV-" + strings.Repeat(strconv.Itoa(digit), 11)
}

func testIDCodeLVAsWritten(digit int) string {
	d := strconv.Itoa(digit)

	return "PNOLV-" + strings.Repeat(d, 6) + "-" + strings.Repeat(d, 5)
}

// createEnvelopeBody posts a create request as a logged-in user and returns the
// status and what the envelope service was asked to store.
func createEnvelopeBody(t *testing.T, body string) (int, string) {
	t.Helper()

	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodPost, contains: "/api/v1/envelopes", status: 201, body: []byte(`{"id":"env-1","status":"draft","version":1,"slotIds":["s-1"]}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))

	const sid, csrf = "invite-sid", "invite-csrf"
	qt.Assert(t, qt.IsNil(app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-1", AccessToken: fakeAccessToken(testIDCodeLV(1)), AccessExpiry: 1 << 62, CSRF: csrf,
	})))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Post("/api/portal/v1/envelopes", []byte(body),
		tc.WithCookie("portal_session", sid), tc.WithHeader("X-CSRF-Token", csrf))
	qt.Assert(t, qt.IsNil(err))
	status := resp.StatusCode()
	responseBody := string(resp.Body())
	fasthttp.ReleaseResponse(resp)

	if status >= 400 {
		return status, responseBody
	}

	return status, string(doer.lastBody)
}

// A code typed with the national separator, with the country chosen beside it,
// reaches the envelope service in the one spelling everything downstream stores
// and compares.
func TestInviteCanonicalisesWhatWasTyped(t *testing.T) {
	status, sent := createEnvelopeBody(t,
		`{"title":"c","slots":[{"orderIndex":1,"identityRef":"`+testIDCodeLVAsWritten(7)+`","country":"LV"}]}`)

	qt.Assert(t, qt.Equals(status, fasthttp.StatusCreated))
	qt.Check(t, qt.IsTrue(strings.Contains(sent, testIDCodeLV(7))))
	qt.Check(t, qt.IsFalse(strings.Contains(sent, testIDCodeLVAsWritten(7))))
}

// A bare national code with the country chosen beside it is what the portal
// actually sends once a person picks their country from the list — and it
// resolves, without anybody having typed "PNO".
func TestInviteTakesTheCountryFromTheChoice(t *testing.T) {
	bare := strings.Repeat("6", 6) + "-" + strings.Repeat("6", 5)
	status, sent := createEnvelopeBody(t,
		`{"title":"c","slots":[{"orderIndex":1,"identityRef":"`+bare+`","country":"LV"}]}`)

	qt.Assert(t, qt.Equals(status, fasthttp.StatusCreated))
	qt.Check(t, qt.IsTrue(strings.Contains(sent, testIDCodeLV(6))))
}

// A country the CODE states wins over the one chosen. A person pasting a
// Lithuanian colleague's code while the list still shows the default stays
// Lithuanian: the same digits in two countries are two people.
func TestInviteCodeCountryWinsOverTheChoice(t *testing.T) {
	lithuanian := "PNOLT-" + strings.Repeat("5", 11)
	status, sent := createEnvelopeBody(t,
		`{"title":"c","slots":[{"orderIndex":1,"identityRef":"`+lithuanian+`","country":"LV"}]}`)

	qt.Assert(t, qt.Equals(status, fasthttp.StatusCreated))
	qt.Check(t, qt.IsTrue(strings.Contains(sent, lithuanian)))
}

// A bare code with no country chosen is REFUSED here rather than relayed. The
// person inviting is the last one who can still answer which country's register
// issued it; after this point nobody can, and a guess files the invitation where
// the person it is for can never claim it.
//
// The answer is this service's ordinary unprocessable-request refusal. Being the
// public-facing boundary, it withholds the detail that names the field, exactly
// as it does for every other rejected request — so the code is what a caller can
// act on, and the screen that collected the value is where a person is told which
// field to fix. What the refusal must never carry is the identity code itself.
func TestInviteRefusesABareCodeWithNoCountry(t *testing.T) {
	bare := strings.Repeat("4", 11)
	status, body := createEnvelopeBody(t,
		`{"title":"c","slots":[{"orderIndex":1,"identityRef":"`+bare+`"}]}`)

	qt.Check(t, qt.Equals(status, fasthttp.StatusUnprocessableEntity))
	qt.Check(t, qt.IsTrue(strings.Contains(body, "err:request:unprocessable")))
	qt.Check(t, qt.IsFalse(strings.Contains(body, bare)))
}

// The add-slot endpoint is the same door and applies the same rule — a rule
// enforced on one of two write paths is not enforced.
func TestAddSlotAppliesTheSameInviteRule(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodPost, contains: "/api/v1/envelopes/env-1/slots", status: 201, body: []byte(`{"id":"s-9"}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))

	const sid, csrf = "addslot-sid", "addslot-csrf"
	qt.Assert(t, qt.IsNil(app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-1", AccessToken: fakeAccessToken(testIDCodeLV(1)), AccessExpiry: 1 << 62, CSRF: csrf,
	})))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Post("/api/portal/v1/envelopes/env-1/slots",
		[]byte(`{"orderIndex":1,"identityRef":"`+strings.Repeat("3", 11)+`"}`),
		tc.WithCookie("portal_session", sid), tc.WithHeader("X-CSRF-Token", csrf))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
	fasthttp.ReleaseResponse(resp)

	resp, err = tc.Post("/api/portal/v1/envelopes/env-1/slots",
		[]byte(`{"orderIndex":1,"identityRef":"`+testIDCodeLVAsWritten(3)+`","country":"LV"}`),
		tc.WithCookie("portal_session", sid), tc.WithHeader("X-CSRF-Token", csrf))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
	fasthttp.ReleaseResponse(resp)

	qt.Check(t, qt.IsTrue(strings.Contains(string(doer.lastBody), testIDCodeLV(3))))
}

// The composed view marks a viewer's own slot by comparing identity KEYS, so a
// slot stored under one spelling is still theirs when their token carries
// another. A person not shown their own slot has no way to find out why.
func TestYouMarkerMatchesAcrossSpellings(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "/api/v1/envelopes/env-1", status: 200, body: []byte(
			`{"envelope":{"id":"env-1","owner":"user-1","status":"sent","version":2},` +
				`"slots":[` +
				`{"id":"s-1","orderIndex":0,"identityRef":"` + testIDCodeLVAsWritten(9) + `"},` +
				`{"id":"s-2","orderIndex":1,"identityRef":"` + testIDCodeLV(8) + `"}` +
				`],"documents":[]}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))

	const sid, csrf = "spelling-sid", "spelling-csrf"
	qt.Assert(t, qt.IsNil(app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-2", AccessToken: fakeAccessToken(testIDCodeLV(9)), AccessExpiry: 1 << 62, CSRF: csrf,
	})))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/envelopes/env-1", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var out composedDetail
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &out)))
	fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.Equals(len(out.Slots), 2))
	qt.Check(t, qt.IsTrue(out.Slots[0].You))
	qt.Check(t, qt.IsFalse(out.Slots[1].You))
}

// The other direction of the same match: the slot is stored canonical — which is
// what every slot written from here on is — and the TOKEN carries the other
// spelling. Both sides must be reduced, not one: a match that works only when the
// difference happens to be on the side you remembered is not a match rule.
func TestYouMarkerMatchesWhenTheTokenCarriesTheOtherSpelling(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodGet, contains: "/api/v1/envelopes/env-1", status: 200, body: []byte(
			`{"envelope":{"id":"env-1","owner":"user-1","status":"sent","version":2},` +
				`"slots":[{"id":"s-1","orderIndex":0,"identityRef":"` + testIDCodeLV(9) + `"}],"documents":[]}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))

	const sid, csrf = "token-spelling-sid", "token-spelling-csrf"
	qt.Assert(t, qt.IsNil(app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-2", AccessToken: fakeAccessToken(testIDCodeLVAsWritten(9)), AccessExpiry: 1 << 62, CSRF: csrf,
	})))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Get("/api/portal/v1/envelopes/env-1", tc.WithCookie("portal_session", sid))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var out composedDetail
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &out)))
	fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.Equals(len(out.Slots), 1))
	qt.Check(t, qt.IsTrue(out.Slots[0].You))
}

// An organisation cannot be invited to sign. A trade-register number is a real
// identity — it is what an e-seal carries — but nobody logs in as an organisation,
// so a slot invited under one is a row no login could ever match: a pending
// signature that will never arrive. The store would accept it, which is exactly why
// the door has to refuse it.
func TestInviteRefusesAnOrganisation(t *testing.T) {
	seal := "NTRLV-" + strings.Repeat("4", 11)
	status, body := createEnvelopeBody(t,
		`{"title":"c","slots":[{"orderIndex":1,"identityRef":"`+seal+`"}]}`)

	qt.Check(t, qt.Equals(status, fasthttp.StatusUnprocessableEntity))
	qt.Check(t, qt.IsTrue(strings.Contains(body, "err:request:unprocessable")))
	// The refusal never repeats the code back: it is personal data, and a rejected
	// request's error text is the least controlled place it could end up.
	qt.Check(t, qt.IsFalse(strings.Contains(body, seal)))
}

// The natural-person types the standard defines are all invitable — the rule is
// "a person", not "a personal number". A passport, an identity card and a tax
// number reach the envelope service unchanged.
func TestInviteAcceptsEveryNaturalPersonType(t *testing.T) {
	for _, code := range []string{
		"PNOLV-" + strings.Repeat("5", 11),
		"PASSK-AB987654",
		"IDCBE-590082394654",
		"TINEL-123456789",
	} {
		t.Run(code, func(t *testing.T) {
			status, sent := createEnvelopeBody(t,
				`{"title":"c","slots":[{"orderIndex":1,"identityRef":"`+code+`"}]}`)

			qt.Assert(t, qt.Equals(status, fasthttp.StatusCreated))
			qt.Check(t, qt.IsTrue(strings.Contains(sent, code)))
		})
	}
}

// The add-slot endpoint is the same door: a rule enforced on one of two write
// paths is not enforced.
func TestAddSlotRefusesAnOrganisationToo(t *testing.T) {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))

	doer := &routingDoer{routes: []routedResponse{
		{method: http.MethodPost, contains: "/api/v1/envelopes/env-1/slots", status: 201, body: []byte(`{"id":"s-9"}`)},
	}}
	app.SetEnvelope(clients.NewEnvelope(doer, "http://envelope:8080", "svc:envelope"))

	const sid, csrf = "seal-sid", "seal-csrf"
	qt.Assert(t, qt.IsNil(app.Sessions().PutSession(context.Background(), sid, &session.Session{
		Subject: "user-1", AccessToken: fakeAccessToken(testIDCodeLV(1)), AccessExpiry: 1 << 62, CSRF: csrf,
	})))

	ta := azugo.NewTestApp(app.App)
	ta.Start(t)
	defer ta.Stop()

	tc := ta.TestClient()
	resp, err := tc.Post("/api/portal/v1/envelopes/env-1/slots",
		[]byte(`{"orderIndex":1,"identityRef":"NTRLV-`+strings.Repeat("6", 11)+`"}`),
		tc.WithCookie("portal_session", sid), tc.WithHeader("X-CSRF-Token", csrf))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
	fasthttp.ReleaseResponse(resp)

	// Nothing reached the envelope service: the refusal is at the door, not downstream.
	qt.Check(t, qt.IsFalse(strings.Contains(string(doer.lastBody), "NTRLV")))
}
