# Changelog

Notable changes to this service, newest first, per release. This file is written for whoever
runs the service or integrates against it.

## v0.1.0

Initial code.

The browser-facing Backend-for-Frontend as first released: the single public trust boundary the
signing portal's SPA talks to — terminates the cookie session, drives the login against the
authorization server, and composes the domain services (documents, signing, envelopes, preview)
into coarse-grained endpoints, each reached on the acting user's behalf. Emits typed security
events at the edge. AGPL-3.0-only.
