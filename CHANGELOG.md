# Changelog

Notable changes to this service, newest first, per release. This file is written for whoever
runs the service or integrates against it.

## v0.2.0

### Changed — a co-signer must be a person, not an organisation

An invitation whose `identityRef` names a **legal person** — a trade-register number (`NTR…`) or any other
organisation identifier — is refused on both invite bodies (`POST /envelopes` and
`POST /envelopes/{id}/slots`) with `422 err:request:unprocessable`. An organisation does not sign: it applies
an e-seal, which is a method one of its people chooses after authenticating as themselves. A slot invited
under an organisation's number could never be matched by any login, so it would sit as a pending signature
that never arrives.

Every **natural-person** identity type is accepted unchanged — `PNO`, `PAS`, `IDC`, `TIN` — in any of the four
spellings, with the country beside a bare code.

**The composed envelope view says who requested the signing, and where each signer goes back.**
When a document system prepared an envelope through the platform's integration API, the envelope
carries an origin — the requester's registered display name and its own reference — and each signer
may carry their own return address. `GET /api/portal/v1/envelopes/{id}` now relays them, so the portal
can show *Requested by Acme DMS* and, after the ceremony, offer *Return to Acme DMS*. **A default
return address the envelope may store on its origin is relayed to nobody** (2026-09-07): the way back
belongs to one signer and travels on that signer's slot, so an outside co-signer is never handed the
requester's location by omission. The view is described below as first shipped, with that one change: the
composed `origin` carries `name` and `ref` only. It lets the portal show the requester and, after the ceremony, offer
*Return to Acme DMS*:

```http
GET /api/portal/v1/envelopes/{id}
{ "envelope": { "id": "…", "status": "sent",
                "origin": { "name": "Acme DMS", "returnUrl": "https://dms.example/return", "ref": "contracts/2026-117" } },
  "slots": [ { "id": "…", "orderIndex": 1, "you": true, "returnUrl": "https://dms.example/contracts/2026-117", … } ] }
```

A signer's own return address is forwarded on the viewer's own slot, and on every slot to the
envelope owner; another party's is not, the same rule the view already applies to identity codes.
An envelope started in the portal has no origin and nothing changes for it: neither key appears.
The return address is data for the app to render as a button — this service performs no redirect
to it. Nothing to configure.

### Changed — the metrics endpoint no longer offers OpenMetrics

A scraper that asked for the OpenMetrics format by sending `Accept: application/openmetrics-text`
used to be answered in it, with the `# EOF` terminator that format requires. This service now
answers in the Prometheus text format whatever the scraper asks for, and writes no `# EOF`:

```http
GET /metrics
Accept: application/openmetrics-text

200 OK
Content-Type: text/plain; version=0.0.4; charset=utf-8
```

**The metric names, labels and values are unchanged**, so Prometheus — and anything else that
accepts the plain-text exposition format — needs nothing done. Two setups need a look: a scrape
configuration that *requires* the OpenMetrics content type, and a check that reads a missing
`# EOF` as a truncated scrape. Both need their expectation relaxed.

The endpoint itself is unchanged otherwise: still `/metrics` (or `METRICS_PATH`), still enabled by
default, and still answered only for trusted addresses (`METRICS_TRUSTED_IPS`, `127.0.0.1` by
default) — so if nothing scrapes this service, there is nothing to do. The change arrives from the
web framework this service is built on rather than from a change of its own, carried in with the
shared libraries below.

### Added — a `country` beside the invited signer's identity code

Both invite bodies now take an optional two-letter `country` beside `identityRef`, and the code is
rewritten to **one canonical spelling** before it is relayed — the identity type, the country, a
hyphen, and the national code with its separators removed:

```http
POST /api/portal/v1/envelopes
Content-Type: application/json

{ "title": "contract", "slots": [ { "orderIndex": 1, "identityRef": "010180-15097", "country": "LV" } ] }
```

The envelope service is asked to store `PNOLV-01018015097`. The same applies to
`POST /api/portal/v1/envelopes/{id}/slots`.

`country` is used **only** when the code names none of its own. A code that already says which
country's register issued it is believed, whatever was chosen — a Lithuanian colleague's
`PNOLT-…` pasted while the list still shows Latvia stays Lithuanian, because the same eleven digits
belong to a different person in a different country.

A code that names no country **and** comes with none is refused with the service's ordinary
`422 err:request:unprocessable`. Nothing is guessed: the person inviting is the last one who can
still answer the question, and an invitation filed under the wrong nationality is one its recipient
can never claim. **The refusal names no field** — this service withholds error detail at the public
boundary, as it does for every rejected request — so the screen that collects the code is where a
person is told what to fix.

### Changed — a signer sees their own slot however each side spells their code

The *this slot is yours* marker on the composed envelope view now compares identity **keys** rather
than text, on both sides: the slot's stored code and the code in the viewer's own token are each
reduced to the one canonical spelling first. A person invited as `PNOLV-010180-15097` who signs in
with a card whose certificate spells it `PNOLV-01018015097` is now shown their slot; before, they
were not, and nothing on the screen said why.

### Notes

- The shared libraries moved to their current releases — the auth client at v0.21.0 and the
  platform kit at v1.11.2 — which carried the web framework, the HTTP stack and the JOSE library up
  with them. No endpoint, field, error or setting of this service changed, and no configuration
  needs touching. The move also clears two published advisories in the cryptography library this
  service depends on; a third has no fix available yet and was already present before the move, and
  the vulnerability scanner reports nothing this service's own code can reach.

### Changed — the shared libraries move to their current releases

`go-platform-kit` v1.11.3, `go-authbyte` v0.23.1, `go-docgate` v1.0.4, `go-gdpr-audit` v1.1.5,
`go-sec-events` v1.2.1 and `go-validation-answer` v1.1.2 (with `go-asice` v1.6.2 arriving indirectly
through the document gate). No endpoint, field, error or setting changes with them, nothing in your
configuration needs touching, and this service's own behaviour is unchanged — the validation answer
it relays has the same shape, and the upload gate admits and refuses exactly what it did before.
`go-sec-events` crosses v1.2.0 on the way, which allows a security event to be emitted from work
with no request behind it — an addition to the library, not a change here.

## v0.1.0

Initial code.

The browser-facing Backend-for-Frontend as first released: the single public trust boundary the
signing portal's SPA talks to — terminates the cookie session, drives the login against the
authorization server, and composes the domain services (documents, signing, envelopes, preview)
into coarse-grained endpoints, each reached on the acting user's behalf. Emits typed security
events at the edge. AGPL-3.0-only.
