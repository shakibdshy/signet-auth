# User deletion removes children explicitly, not by database cascade

Deleting a User explicitly revokes its Sessions, deletes its Accounts and deletes its Tokens of every kind before removing the User row. Only relying on database `ON DELETE CASCADE` would work for the bundled SQLite/PostgreSQL migrations, but accounts and sessions cascade there while tokens have no foreign key at all — and applications own their schema. Explicit deletion is the only behaviour that holds for bring-your-own-schema Stores and for Tokens. The bundled migrations' cascade remains a harmless backstop.
