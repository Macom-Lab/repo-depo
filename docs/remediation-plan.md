# Remediation Plan

This plan covers findings that remain open or are accepted after the current
implementation. Fixed items are documented in `findings.md` and protected by
regression tests.

| Finding | Residual risk | Required remediation and effort | Compensating controls | Target / owner |
| --- | --- | --- | --- | --- |
| VT-12: Unfixed Debian Perl advisories | Two critical and two high advisories remain in the pinned base. VulnTracker does not invoke Perl, but a future dependency or attacker with code execution could reach the affected runtime. | Rebuild on every base-image update and rescan. Move to a smaller distroless or custom Python runtime if the next Debian update does not remove the package. Estimated effort: 1-2 days to prototype and validate a distroless build; minutes for a normal patched rebuild. | Non-root UID, no Linux capabilities, read-only application filesystem, seccomp, resource limits, ingress restriction, and no application use of Perl. | Platform engineering; rebuild immediately when a fix is published, otherwise reassess in 30 days. |
| VT-13: Share password in query string | Passwords may appear in local browser history and in access logs controlled by infrastructure outside this repository. Exposure is limited to one report and a maximum of 24 hours. | Version the API to accept the password in a POST body or dedicated header, update external clients, and configure gateway-wide query-string redaction before enabling legacy compatibility. Estimated effort: 2-4 days including client migration. | High-entropy share token, slow password hashing, 24-hour expiry, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, generic invalid-link responses, and TLS-only production ingress. | API and edge teams; next API version. |
| VT-14: No distributed authentication rate limit | Credential stuffing and repeated share-password guesses can consume CPU and may compromise weak user passwords. A process-local counter would be bypassed by pod restarts or additional replicas. | Add gateway limits by source and route, plus Redis-backed per-account counters with bounded lockout. Add MFA or an external identity provider before production. Estimated effort: 3-5 days for rate limiting; 1-2 sprints for managed identity and MFA. | Bcrypt/PBKDF2 slow verification, equal-cost unknown-user checks, short-lived JWTs, generic failures, request-size limits, and pod resource limits. | Identity/platform teams; required before public exposure. |
| Share links have no explicit revocation endpoint | A mistakenly shared or copied link remains valid until expiry unless the scan is deleted. | Add an authenticated list/revoke API, store revocation audit events, and expose it in the user workflow. Estimated effort: 1-2 days. | Maximum 24-hour lifetime; deleting the scan cascades to all links; tokens are unguessable and stored only as digests. | API team; next feature increment. |
| Notification registry is in memory | Webhook registrations disappear on restart and a compromised service instance can alter its local registry. This is mainly an availability and integrity risk, not direct scan-data persistence. | Move registrations to the primary database with tenant ownership, encrypted destination storage, change audit, and migration tests. Estimated effort: 3-5 days. | Notification endpoints require a strong service key; destinations are validated at registration and again at dispatch. | Integrations team; before multi-replica deployment. |
| VT-15: Bandit B105 false positive | No credential exists; the risk is alert fatigue only. | No code remediation. Keep the finding visible rather than adding a broad suppression. If policy requires a baseline, suppress only this exact line with a written justification. | Manual review confirmed `"bearer"` is a protocol label. Secret values are absent from source and provided by mounted files. | Security engineering; review if the line changes. |

## Operational acceptance criteria

Production release should be blocked unless:

1. The image is rebuilt from the pinned base and rescanned within 24 hours of release.
2. No fixable critical or high dependency finding remains.
3. Edge rate limiting and query-string redaction are enabled and tested.
4. The External Secrets controller and secret-store identity are operational.
5. The deployed image digest matches the reviewed build and the health probes pass.
6. Backup, restore, alerting, and credential-rotation procedures have been exercised.
