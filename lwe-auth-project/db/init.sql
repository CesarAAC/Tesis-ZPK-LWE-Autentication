-- UUID generation for authentication challenge identifiers.
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Public material only. Private keys must remain on the prover/client side.
CREATE TABLE IF NOT EXISTS public_keys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    protocol_name VARCHAR(30) NOT NULL,
    key_data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auth_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    protocol_name VARCHAR(30) NOT NULL,
    challenge_data JSONB NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'SUCCESS', 'FAILED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_public_keys_user_protocol
    ON public_keys (user_id, protocol_name);

CREATE INDEX IF NOT EXISTS idx_auth_challenges_user_status
    ON auth_challenges (user_id, status);

-- Benchmark tables. The db directory is mounted read-only at /db by Compose.
\i /db/migrations/001_benchmarking.sql
