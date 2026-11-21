# Session freshness uses creation time, not last-seen time

Freshness checks measure the time since a Session's `CreatedAt` — the moment the
User authenticated — rather than `LastSeenAt`, which is extended on every
request. Signet touches `LastSeenAt` to enforce the idle timeout, so a Session
that has been active for hours would wrongly appear freshly authenticated if
freshness used that field. `CreatedAt` is never updated, so it gives the
"authenticated within N seconds" semantics that freshness checks require, with
no schema change across adapters or bring-your-own-schema Stores.
