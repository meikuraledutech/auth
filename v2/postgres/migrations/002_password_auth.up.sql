ALTER TABLE auth_users
    ADD COLUMN IF NOT EXISTS password_hash TEXT;

CREATE TABLE IF NOT EXISTS auth_password_resets (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    used        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_password_resets_user    ON auth_password_resets(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_password_resets_hash    ON auth_password_resets(token_hash);
CREATE INDEX IF NOT EXISTS idx_auth_password_resets_expires ON auth_password_resets(expires_at) WHERE used = FALSE;
