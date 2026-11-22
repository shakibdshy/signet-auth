# The Store is authoritative; a Session cache is optional bounded staleness

A Session cache is off by default. When enabled, it is a read-through copy with a configured
lifetime capped by the Session's idle timeout: a cache hit skips the Store until that lifetime
expires, so a revocation performed by another process may take up to that lifetime to be
observed. Cache failures are logged and fall back to the Store; Store failures reject the
request. Secondary storage is not a new abstraction — a Redis-backed adapter simply implements
the existing `Store` interface.

We considered making the cache authoritative (fastest, but permanent revocation lag until
expiry) and requiring every deployer to run one (fast, but a new required concept and a new
failure mode for every adopter). Both were rejected: Signet is an embeddable library whose
callers have different threat models, so it must not silently weaken revocation or force
infrastructure on them. The cost of this choice is that adopters who enable the cache must
choose their own acceptable Revocation lag; that is a deliberate, visible setting rather than a
hidden guarantee.
