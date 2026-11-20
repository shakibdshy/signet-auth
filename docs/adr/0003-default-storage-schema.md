# Default storage schema with explicit migrations

The bundled storage adapters ship an embedded, `signet_`-prefixed default schema and an explicit `Migrate` method; they never auto-migrate on connection. Applications that already own a users table implement the narrow Store contracts directly instead of configuring table and column names on the adapters.

We rejected auto-migration because authentication tables hold security-critical state and schema changes must stay under the application's control. We also rejected configurable column mapping: it would turn each adapter into a mini ORM and blur the "bring your own schema" boundary. The prefix avoids collisions in shared databases. The consequence is that applications using the default schema must call `Migrate` themselves, and custom schemas need their own Store implementation.
