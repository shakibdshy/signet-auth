# Authorization state stays application-managed

Signet provides the authorization vocabulary — Role, Permission, Organization, Membership, API key and the checks around them — through optional interfaces and callbacks. It persists no authorization state itself: an application supplies an `Authorizer` for roles and permission checks, an `APIKeyStore` for hashed API keys, and an `OrganizationStore` for organizations and memberships. The active organization is carried in a signed cookie rather than a Session column.

We considered bundling tables and Store methods for roles, keys and organizations, as framework-oriented libraries do. That would force a schema migration on every adopter, including those who only want password auth, and would make Signet own retention and policy decisions it cannot make for its adopters. The cost is that applications using Phase 5 must implement three small adapters, but the default path keeps its current schema, Store contract and dependency footprint.
