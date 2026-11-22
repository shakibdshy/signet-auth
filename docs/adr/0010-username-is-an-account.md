# A Username is an Account, not a User column

A chosen Username is stored as an Account with a fixed provider name and the normalized identifier as its provider user ID. Sign-in resolves it with the existing provider-account lookup; listing and unlinking use the existing account methods. No User column or schema migration is needed.

We considered storing a username on the User row, as other libraries do. That would require a migration in every bundled store and in every bring-your-own-schema implementation, plus a second mutation path for changing it. Modeling it as an Account matches the domain definition of an Account as a named way a User authenticates, makes a username changeable through the same unlink-and-add path, and keeps the Store contract unchanged. The cost is that a username is not a first-class field on User, so callers must use the account API to read it.
