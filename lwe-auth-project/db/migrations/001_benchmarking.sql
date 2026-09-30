-- Benchmarking schema. Idempotent so it can be applied to existing local volumes.
CREATE TABLE IF NOT EXISTS benchmark_experiments (
    id UUID PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    git_commit VARCHAR(64) NOT NULL,
    git_dirty BOOLEAN NOT NULL DEFAULT FALSE,
    config JSONB NOT NULL,
    config_sha256 VARCHAR(64),
    environment JSONB NOT NULL,
    protocol_order JSONB NOT NULL DEFAULT '[]'::jsonb,
    client_started_at TIMESTAMPTZ,
    client_finished_at TIMESTAMPTZ,
    notes TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'RUNNING'
        CHECK (status IN ('RUNNING', 'SUCCESS', 'FAILED')),
    started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMPTZ
);

-- Existing development volumes may predate the reproducibility fields.
ALTER TABLE benchmark_experiments
    ADD COLUMN IF NOT EXISTS config_sha256 VARCHAR(64),
    ADD COLUMN IF NOT EXISTS protocol_order JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS client_started_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS client_finished_at TIMESTAMPTZ;

-- Historical development rows cannot recover the old config hash. Mark them
-- explicitly instead of pretending to know it, then enforce the invariant for
-- all new runs.
UPDATE benchmark_experiments
SET config_sha256 = repeat('0', 64)
WHERE config_sha256 IS NULL;

ALTER TABLE benchmark_experiments
    ALTER COLUMN config_sha256 SET NOT NULL;

CREATE TABLE IF NOT EXISTS benchmark_protocol_runs (
    id UUID PRIMARY KEY,
    experiment_id UUID NOT NULL
        REFERENCES benchmark_experiments(id) ON DELETE CASCADE,
    protocol_name VARCHAR(50) NOT NULL,
    display_name VARCHAR(120) NOT NULL,
    parameters JSONB NOT NULL,
    conformance_checks JSONB NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'RUNNING'
        CHECK (status IN ('RUNNING', 'SUCCESS', 'FAILED')),
    error_message TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMPTZ,
    UNIQUE (experiment_id, protocol_name)
);

CREATE TABLE IF NOT EXISTS benchmark_measurements (
    id BIGSERIAL PRIMARY KEY,
    protocol_run_id UUID NOT NULL
        REFERENCES benchmark_protocol_runs(id) ON DELETE CASCADE,
    category VARCHAR(50) NOT NULL,
    operation VARCHAR(80) NOT NULL,
    metric_name VARCHAR(80) NOT NULL,
    iteration INTEGER,
    value DOUBLE PRECISION NOT NULL,
    unit VARCHAR(24) NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS benchmark_summaries (
    id BIGSERIAL PRIMARY KEY,
    protocol_run_id UUID NOT NULL
        REFERENCES benchmark_protocol_runs(id) ON DELETE CASCADE,
    category VARCHAR(50) NOT NULL,
    operation VARCHAR(80) NOT NULL,
    metric_name VARCHAR(80) NOT NULL,
    unit VARCHAR(24) NOT NULL,
    sample_count INTEGER NOT NULL CHECK (sample_count > 0),
    mean DOUBLE PRECISION NOT NULL,
    median DOUBLE PRECISION NOT NULL,
    stddev DOUBLE PRECISION NOT NULL,
    minimum DOUBLE PRECISION NOT NULL,
    p95 DOUBLE PRECISION NOT NULL,
    p99 DOUBLE PRECISION NOT NULL,
    maximum DOUBLE PRECISION NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Evidence-backed qualitative criteria used by the thesis. No global
-- easy/medium/hard score is imposed; every criterion is stored with evidence.
CREATE TABLE IF NOT EXISTS benchmark_protocol_assessments (
    id BIGSERIAL PRIMARY KEY,
    protocol_run_id UUID NOT NULL
        REFERENCES benchmark_protocol_runs(id) ON DELETE CASCADE,
    dimension VARCHAR(40) NOT NULL
        CHECK (dimension IN ('implementation', 'operational', 'trust_architecture', 'maturity', 'security')),
    criterion VARCHAR(100) NOT NULL,
    value JSONB NOT NULL,
    evidence TEXT NOT NULL,
    source VARCHAR(200),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Security estimates are deliberately separate from performance measurements.
-- They must come from an estimator, standard, paper or other explicit evidence;
-- the benchmark runner never invents security-bit values.
CREATE TABLE IF NOT EXISTS benchmark_security_assessments (
    id BIGSERIAL PRIMARY KEY,
    protocol_run_id UUID NOT NULL
        REFERENCES benchmark_protocol_runs(id) ON DELETE CASCADE,
    assessment_type VARCHAR(50) NOT NULL,
    tool_or_source VARCHAR(200) NOT NULL,
    tool_version VARCHAR(80),
    classical_security_bits DOUBLE PRECISION,
    quantum_security_bits DOUBLE PRECISION,
    assumptions JSONB NOT NULL DEFAULT '{}'::jsonb,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_benchmark_runs_experiment
    ON benchmark_protocol_runs (experiment_id);

CREATE INDEX IF NOT EXISTS idx_benchmark_measurements_lookup
    ON benchmark_measurements (protocol_run_id, category, operation, metric_name);

CREATE INDEX IF NOT EXISTS idx_benchmark_summaries_lookup
    ON benchmark_summaries (protocol_run_id, category, operation, metric_name);

CREATE INDEX IF NOT EXISTS idx_benchmark_protocol_assessments_lookup
    ON benchmark_protocol_assessments (protocol_run_id, dimension, criterion);

CREATE INDEX IF NOT EXISTS idx_benchmark_security_assessments_lookup
    ON benchmark_security_assessments (protocol_run_id, assessment_type);

CREATE INDEX IF NOT EXISTS idx_benchmark_experiments_started
    ON benchmark_experiments (started_at DESC);
