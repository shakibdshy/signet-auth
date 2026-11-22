# TOTP state requires an optional store and a dedicated key

TOTP secrets and Backup codes are held in an application-supplied `TOTPStore`, enabled only when the application also supplies a dedicated 32-byte key. Secrets are encrypted with that key and Backup codes are stored only as digests. Neither the key nor the store is required by default; without them, Second factor sign-in is unavailable.

We considered adding TOTP columns to the User table and reusing the single-use Token store. Columns would force a migration on every adapter and on bring-your-own-schema Stores for a feature most applications will not enable. The Token store cannot serve a long-lived secret that must be read back to verify each code. The cost of this choice is that an adopter who wants 2FA must supply one small adapter and protect one more key, but every other adopter pays nothing.
