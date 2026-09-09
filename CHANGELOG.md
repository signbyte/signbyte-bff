# Changelog

Notable changes to this service, newest first, per release. This file is written for whoever
runs the service or integrates against it.

## v0.2.0

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

### Notes

- The shared libraries moved to their current releases — the auth client at v0.21.0 and the
  platform kit at v1.11.2 — which carried the web framework, the HTTP stack and the JOSE library up
  with them. No endpoint, field, error or setting of this service changed, and no configuration
  needs touching. The move also clears two published advisories in the cryptography library this
  service depends on; a third has no fix available yet and was already present before the move, and
  the vulnerability scanner reports nothing this service's own code can reach.

## v0.1.0

Initial code.

The browser-facing Backend-for-Frontend as first released: the single public trust boundary the
signing portal's SPA talks to — terminates the cookie session, drives the login against the
authorization server, and composes the domain services (documents, signing, envelopes, preview)
into coarse-grained endpoints, each reached on the acting user's behalf. Emits typed security
events at the edge. AGPL-3.0-only.
