# Security policy

This is the browser-facing service of the signbyte electronic signing portal: the one
internet-facing edge in front of the rest of the platform, which makes its security surface
the whole product's security surface.

Please report security problems privately. Do not open a public issue, pull request or discussion
for anything that could be exploited before a fix exists.

## How to report

Use **[private vulnerability reporting](https://github.com/signbyte/signbyte-bff/security/advisories/new)** on
this repository. The report stays visible only to you and the maintainers until an advisory is
published, and it gives us one place to discuss and co-ordinate a fix with you.

Please include, as far as you can establish it:

- what the problem is, and what an attacker gains from it;
- the smallest set of steps that reproduces it, and against which version or commit;
- the configuration it needs, if it only appears under particular settings;
- whether you have told anyone else, and whether a disclosure date already binds you.

## What happens next

- We acknowledge a report within **five working days**.
- We tell you whether we can reproduce it, and what we think its severity is, as soon as we know.
- We keep you updated while a fix is prepared, and we agree a disclosure date with you. Our default
  is to publish an advisory once a fix is available, and in any case within **90 days** of the
  report — earlier if the problem is already public or being exploited.
- We credit you in the advisory unless you would rather stay anonymous.

There is no bug-bounty programme. We are grateful anyway, and we say so publicly.

## What we consider most serious

This is software for **qualified electronic signatures**, so the classes of problem that matter most
are the ones that undermine what a signature is supposed to prove:

- producing a signature, or a validation result, that a signer did not authorise;
- making an invalid signature validate, or a valid one appear invalid;
- reaching another person's documents, signing tasks or identity data;
- influencing which trust anchors or revocation data are used;
- exposing, reusing or forging session, delegation or signing credentials;
- weakening or bypassing the audit records that are meant to be evidence.

Denial of service and findings that need an already-compromised host or an already-authenticated
administrator are in scope but lower priority. Reports about outdated dependencies are welcome only
where you can show the vulnerable path is actually reachable.

## Scope

This policy covers the code in this repository. It does not cover third-party services the software
talks to — report those to the parties that run them — and it does not cover deployments operated by
someone other than us; ask their operator.

## Releases

The project has not yet published a release. Security fixes land on the default branch, and once
releases exist this section will name the versions that receive them.
