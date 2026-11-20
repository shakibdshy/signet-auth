CREATE TABLE IF NOT EXISTS signet_users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    name TEXT NOT NULL DEFAULT '',
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_signet_users_email ON signet_users(email);

CREATE TABLE IF NOT EXISTS signet_accounts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    email TEXT NOT NULL DEFAULT '',
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    password_hash TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (provider, provider_user_id),
    FOREIGN KEY (user_id) REFERENCES signet_users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_signet_accounts_user ON signet_accounts(user_id);

CREATE TABLE IF NOT EXISTS signet_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    idle_expires_at TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    FOREIGN KEY (user_id) REFERENCES signet_users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_signet_sessions_user ON signet_sessions(user_id);

CREATE TABLE IF NOT EXISTS signet_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (kind, hash)
);

CREATE INDEX IF NOT EXISTS idx_signet_tokens_user_kind ON signet_tokens(user_id, kind);
