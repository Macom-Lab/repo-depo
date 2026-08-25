# Executive Security Summary

Before this review, a signed-in user could read another customer's vulnerability
records, attackers could forge user sessions, reusable credentials were stored
in source code, and the notification service could be used to reach internal
systems. Those direct paths to customer-data loss and internal compromise have
been closed. Shared reports now expire, can be password protected, expose only
the intended record, and are deployed with tightly limited runtime permissions.

The original posture was not suitable for production because several controls
depended on the service being “internal.” The updated design authenticates
service-to-service calls, isolates each user's records, validates every outbound
webhook destination, removes committed credentials, rejects unsigned sessions,
and provides a hardened container and Kubernetes deployment. Automated tests
cover the security boundaries, and final source, dependency, and deployment
checks have no actionable high-severity findings in application code or pinned
dependencies.

## Top three residual risks

1. **Automated password attacks remain possible.** Login and public shared-report
   password checks need a distributed rate limit and, for user accounts, a
   stronger identity control such as MFA. This was not implemented because a
   reliable limit must live in shared gateway or datastore infrastructure, not
   in one application process.

2. **The base operating system contains four serious Perl advisories with no
   vendor fix.** The application does not use Perl, and the container runs
   without root privileges or write access to its code, which lowers practical
   exposure. The image must be rebuilt as soon as Debian publishes patched
   packages; a smaller custom runtime is the fallback if fixes remain delayed.

3. **The required shared-report password interface can leak credentials into
   browser history or upstream logs.** The report is limited to one record and
   24 hours, and responses cannot be cached or send referrers. Fully removing
   the risk requires a versioned interface change plus log redaction across the
   ingress and observability stack.

## Recommended next steps

Before external production use, place both services behind centrally managed
rate limits, connect user login to an identity provider with MFA, and enable
query-string redaction. Establish daily image rebuilds and fail release gates
for fixable critical or high findings. Replace the prototype database and
in-memory webhook registry with durable managed storage, then test backup and
restore.

Within the next release cycle, add shared-link listing and revocation, webhook
change auditing, service-key rotation, and security event alerting. Run an
independent penetration test focused on tenant isolation, session handling,
shared links, and outbound webhooks. Ownership for every accepted risk and its
deadline should be recorded in the production risk register.
