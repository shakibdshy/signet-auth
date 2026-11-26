# Session client info is a column on the Session record

A Session stores the raw `User-Agent` of the request that created it, truncated
and exposed read-only through `SessionInfo`, so integrators can show which
client started each visit. This is the first Session column added after the
bundled schema shipped: ADR-0009, ADR-0010 and ADR-0013 each avoided columns to
spare bring-your-only-schema Stores a migration, and that stance still holds
for opt-in features — but a Session property that every Session carries is part
of the record, not an optional control, so it belongs in the table. The Store
contract is unchanged (`CreateSession` already takes the whole `Session`), so
existing custom Stores keep compiling; they just persist the new field to keep
the conformance suite green. Migrations stay bookkeeping-free and replay-safe:
an append-only `0002` per adapter, where Postgres uses `ADD COLUMN IF NOT
EXISTS` and SQLite applies a guarded `ALTER TABLE` from the adapter because it
has no `IF NOT EXISTS` form. The alternative — recording the agent only in a
cookie or an optional side store — was rejected because `GET /sessions` must
show it for Sessions created by any flow, not just the caller's browser.
