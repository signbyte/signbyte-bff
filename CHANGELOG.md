# Changelog

Notable changes to this service, newest first, per release. This file is written for whoever
runs the service or integrates against it.

## v0.2.0

**The composed envelope view says who requested the signing, and where each signer goes back.**
When a document system prepared an envelope through the platform's integration API, the envelope
carries an origin — the requester's registered display name, its default return address, its own
reference — and each signer may carry their own return address. `GET /api/portal/v1/envelopes/{id}`
now relays them, so the portal can show *Requested by Acme DMS* and, after the ceremony, offer
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

## v0.1.0

Initial code.

The browser-facing Backend-for-Frontend as first released: the single public trust boundary the
signing portal's SPA talks to — terminates the cookie session, drives the login against the
authorization server, and composes the domain services (documents, signing, envelopes, preview)
into coarse-grained endpoints, each reached on the acting user's behalf. Emits typed security
events at the edge. AGPL-3.0-only.
