# Prioritised Security Findings

## Scope and method

The review covered both application services, the Python and Node dependency
sets, the built Python container, and the rendered Helm resources. Automated
results are preserved without editing in `reports/`; the table below adds the
application-specific judgment that raw scanner output cannot provide.

Final scan summary:

| Category | Tool | Final result |
| --- | --- | --- |
| SAST | Bandit 1.9.4 | One low-severity false positive; no medium/high findings |
| Python SCA | pip-audit 2.10.1 | 9 direct pinned packages, 0 known vulnerabilities |
| Node SCA | npm audit | 68 production packages, 0 known vulnerabilities |
| Container | Docker Scout 1.24.0 | 36 advisories: 2 critical, 2 high, 4 medium, 25 low, 3 unspecified |
| IaC | Checkov 3.3.13 | 96 passed, 0 failed across 7 rendered resources |

## Findings

| ID | Source | Severity and rationale | Business impact | Origin | Status |
| --- | --- | --- | --- | --- | --- |
| VT-01 | Manual review | **Critical.** Scan reads and searches did not enforce `owner_id`, allowing authenticated cross-tenant access by changing an identifier or search term. | A customer or auditor could retrieve another customer's vulnerability titles, affected components, remediation notes, and CVE data. This is a direct confidentiality breach. | Starter code | **Fixed.** Ownership filters now cover list, search, read, update, delete, and share creation; foreign objects return the same 404 as missing objects. |
| VT-02 | Manual review | **Critical.** The search query was interpolated into raw SQL. The endpoint was remotely reachable after ordinary login and exposed a classic injection boundary. | An attacker could bypass intended filters, read other customers' findings, and potentially alter or destroy data on a more capable production database. | Starter code | **Fixed.** Search uses bound ORM expressions, escapes LIKE metacharacters, is tenant-scoped, and limits results. |
| VT-03 | Manual review | **Critical.** JWT decoding explicitly accepted the `none` algorithm and did not require issued-at, expiry, subject, or token-type claims. | Forged tokens could impersonate any user and expose or modify all vulnerability records available to that identity. | Starter code | **Fixed.** The algorithm is fixed to HS256, required claims and token type are validated, production secrets must be strong, and regression tests reject unsigned and incomplete tokens. |
| VT-04 | Manual review | **Critical.** Reusable database, signing, and internal-service credentials were committed in source. | Anyone with repository access could forge sessions or reuse service credentials in a connected environment; rotation would be mandatory after exposure. | Starter code | **Fixed.** Hardcoded credentials were removed. Production fails closed when required secrets are absent, and Helm sources them from an external secrets manager and mounts them as files. |
| VT-05 | Manual review | **Critical.** The notification service accepted unauthenticated webhook registration, listing, deletion, and dispatch requests. | An external caller could redirect or trigger notifications, enumerate integration targets, and use the service as an attack relay. | Starter code | **Fixed.** Sensitive routes require a constant-time-checked service key; the Python caller authenticates every notification request. |
| VT-06 | Manual review | **Critical.** Arbitrary webhook URLs were fetched without protocol, address, or DNS validation. | An attacker could make the service contact cloud metadata, localhost, or private administrative systems and exfiltrate responses through timing or delivery behavior. | Starter code | **Fixed.** Only approved HTTPS ports and public addresses are allowed; every DNS answer is checked, dispatch revalidates the target, and the connection is pinned to validated addresses to resist DNS rebinding. |
| VT-07 | Manual review | **High.** Failed logins included the supplied password in logs, while unhandled API and notify errors returned internal exception details. | Central logs or error responses could disclose passwords, internal paths, configuration, or dependency behavior to operators and attackers. | Starter code | **Fixed.** Authentication logs identifiers only, public 500 responses are generic, and Express stack traces are not returned. |
| VT-08 | Manual review of Task 1 | **High.** A shared-report capability would become a reusable data-breach primitive if predictable or stored in recoverable form; optional passwords create the same risk if stored directly or hashed too quickly. | Database read access or token guessing could expose customer vulnerability reports outside the authenticated application. | New feature | **Fixed.** Tokens contain 256 bits of randomness and only their SHA-256 digests are stored; passwords use 600,000-round PBKDF2-SHA256; links are owner-created, read-only, non-cacheable, and expire after 24 hours. |
| VT-09 | npm audit / SCA | **High.** Express 4.18.2 pulled vulnerable request parsing and route-matching components with network denial-of-service paths; `uuid` 9.0.0 was also vulnerable and unnecessary. | Crafted requests could exhaust the small notification service and interrupt vulnerability notifications. | Starter dependencies | **Fixed.** Express is pinned to 4.22.2 and Node's built-in `crypto.randomUUID()` replaces the external UUID package. The final audit reports zero vulnerabilities. |
| VT-10 | pip-audit and container scan / SCA | **High.** The original test runner pin and the original JWT dependency tree included known vulnerable releases, including an unfixed ECDSA implementation that the service did not need. | A compromised or unstable build environment could affect CI availability; retaining unused cryptographic code increases attack surface and patch burden. | Starter dependencies | **Fixed.** Development dependencies are separated from the runtime image, pytest is pinned to 9.0.3, and PyJWT 2.13.0 replaces the ECDSA-bearing stack. The final Python audit is clean. |
| VT-11 | Checkov / IaC | **High.** The first rendered chart exposed secrets through environment variables, allowed tag-only images, and did not make the namespace explicit. | Pod-inspection access could reveal credentials, mutable tags could deploy unreviewed code, and default-namespace use weakens operational isolation. | New deployment artifacts | **Fixed.** Secrets are mounted read-only, the image is digest-pinned with `Always` pull policy, the namespace is explicit, and the final scan has 96 passing checks and no failures. |
| VT-12 | Docker Scout / container | **High residual (scanner: 2 critical, 2 high).** Four Perl advisories remain in Debian 13 with no fixed package version. Exploitability is lower than the generic score because VulnTracker does not invoke Perl and the container is non-root and read-only. | If a future runtime path invokes affected Perl functionality, compromise could affect API availability or the data accessible to that pod. | Pinned base image | **Accepted temporarily.** See `remediation-plan.md`; rebuild immediately when Debian publishes fixes. |
| VT-13 | Manual review of Task 1 | **Medium.** The assignment requires the share password as a query parameter, which can be retained by browser history or upstream request logs. | A user with access to those records could open the report until its 24-hour expiry. | New feature / required interface | **Partially mitigated.** Responses disable caching and referrers and tokens expire quickly; changing the request contract requires client coordination. |
| VT-14 | Manual review | **High.** Login and public share-password checks do not have a distributed rate limit or account lockout. Slow password hashing raises attack cost but does not bound repeated attempts. | Internet exposure could permit credential stuffing, account takeover, or resource exhaustion. | Starter architecture and new public endpoint | **Deferred.** A correct control needs a shared counter at the ingress or gateway; see `remediation-plan.md`. |
| VT-15 | Bandit / SAST | **Informational.** B105 reports the literal `"bearer"` token type as a possible hardcoded password. It is an OAuth token-type label, not a credential. | None. Suppressing it globally could hide real hardcoded secrets in future scans. | Starter authentication response | **False positive; not suppressed.** Retained visibly in the raw report. |

## Prioritisation notes

The six critical starter-code findings were addressed before deployment work
because each could directly expose customer findings or turn the notification
service into an internal-network relay. Dependency and deployment hardening
then reduced supply-chain and operational exposure. Residual scanner severity
is not treated as exploitability: the remaining container advisories have no
vendor fix, very low published exploitation probability, and no application
code path, but are still tracked because the affected package ships in the
runtime image.
