# Requirements coverage — Phase 5

Source: issue #30.

## Testing Decisions → tests

| Spec line (short quote) | Test |
| --- | --- |
| one seam: public Store interface | `TestStorePassesConformance` in both adapter packages |
| real databases are infrastructure | testcontainers in `store/postgres/postgres_test.go`; in-memory DB in `store/sqlite/sqlite_test.go` |
| migration success proven by conformance after Migrate | `TestStorePassesConformance` in both adapter packages |
| every narrow contract | `TestStorePassesConformance/users`, `/accounts`, `/sessions`, `/tokens` |
| not-found behaviour | `TestStorePassesConformance/users`, `/accounts`, `/sessions`, `/tokens` |
| session revocation | `TestStorePassesConformance/sessions` |
| token replay detection | `TestStorePassesConformance/tokens` |
| concurrent token consumption | `TestStorePassesConformance/token_concurrency` |
| in-memory reference validation | `TestReferenceStorePassesConformance` |
| idempotent migrations | second `Migrate` call in both `TestStorePassesConformance` tests |
| skipped Postgres tests without Docker | `TestStorePassesConformance` in `store/postgres` |

## Security requirements → tests

| Requirement | Test or explained limitation |
| --- | --- |
| single-use Token under concurrency | `TestStorePassesConformance/token_concurrency` |
| consumed Token remains visible for replay detection | `TestStorePassesConformance/tokens` |
| session revocation works against a real database | `TestStorePassesConformance/sessions` |
| no DSN or credentials logged | **limitation:** adapters contain no logging calls and Store holds no DSN; negative property verified by inspection, not a runtime assertion |
| pure-Go SQLite | driver import in `store/sqlite/sqlite_test.go`; no cgo dependency in the module |

## Security mechanisms → effect tests

| Mechanism | Observable effect asserted | Test |
| --- | --- | --- |
| atomic `ConsumeToken` | exactly one of 16 concurrent callers wins | `TestStorePassesConformance/token_concurrency` |
| token replay detection | second consume fails, row remains visible with `UsedAt` | `TestStorePassesConformance/tokens` |
| explicit migrations | conformance passes on a freshly migrated database | `TestStorePassesConformance` |
| multi-statement migration | conformance passes after applying a migration file with several statements | `TestStorePassesConformance` in both adapters |
| foreign keys and cascade | **limitation:** default schemas declare FKs; cascade behaviour is a schema detail, not a Store contract, so conformance does not assert it |

## Cross-cutting sweep

- [x] every Store method covered by a conformance case (including DeleteSession)
- [x] concurrency asserted with an observable winner count
- [x] migration effect asserted through conformance, not SQL text
- [x] no driver DSN or credential persisted on Store
- [x] integration skip behaviour asserted on a machine without Docker
- [x] config defaults unaffected (no Store interface changes this phase)
