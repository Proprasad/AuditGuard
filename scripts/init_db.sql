-- AuditGuard Canonical Relational Schema v2 (PostgreSQL 16 DDL)
-- Exact fixed-point TEXT money storage, single-use approval tokens, RBAC users, and memory stores.

CREATE TABLE IF NOT EXISTS banks (
    bank_id TEXT PRIMARY KEY,
    bank_name TEXT NOT NULL,
    ifsc_prefix TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS customers (
    customer_id TEXT PRIMARY KEY,
    full_name TEXT NOT NULL,
    synthetic_pan_hash TEXT UNIQUE NOT NULL,
    kyc_tier TEXT CHECK (kyc_tier IN ('FULL', 'MINIMAL', 'EXPIRED')),
    occupation TEXT NOT NULL,
    declared_annual_income_inr TEXT NOT NULL,
    risk_rating TEXT CHECK (risk_rating IN ('LOW', 'MEDIUM', 'HIGH')),
    onboarding_date TEXT NOT NULL,
    kyc_notes TEXT
);

CREATE TABLE IF NOT EXISTS commercial_registry (
    registry_id TEXT PRIMARY KEY,
    customer_id TEXT REFERENCES customers(customer_id),
    entity_type TEXT CHECK (entity_type IN ('MARKETPLACE', 'EMPLOYER', 'NGO_80G', 'CHIT_FUND', 'MERCHANT')),
    registration_number TEXT UNIQUE NOT NULL,
    status TEXT CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED')),
    registered_since TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT PRIMARY KEY,
    bank_id TEXT REFERENCES banks(bank_id),
    customer_id TEXT REFERENCES customers(customer_id),
    account_type TEXT CHECK (account_type IN ('SAVINGS', 'CURRENT', 'ESCROW', 'SALARY')),
    status TEXT CHECK (status IN ('ACTIVE', 'DORMANT', 'FROZEN')),
    opened_date TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions (
    txn_id TEXT PRIMARY KEY,
    from_account_id TEXT REFERENCES accounts(account_id),
    to_account_id TEXT REFERENCES accounts(account_id),
    amount_inr TEXT NOT NULL,
    txn_timestamp TEXT NOT NULL,
    channel TEXT CHECK (channel IN ('IMPS', 'NEFT', 'RTGS', 'UPI')),
    memo_text TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    seed_account_id TEXT REFERENCES accounts(account_id),
    triggered_at TEXT NOT NULL,
    rule_triggered TEXT NOT NULL,
    initial_amount_inr TEXT NOT NULL,
    network_accounts_json TEXT NOT NULL DEFAULT '[]',
    status TEXT DEFAULT 'OPEN'
);

CREATE TABLE IF NOT EXISTS worksheets (
    worksheet_id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL,
    content_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending_review',
    reviewer_id TEXT,
    reviewer_decision TEXT,
    reviewer_notes TEXT,
    thread_id TEXT,
    revision INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    alert_id TEXT UNIQUE NOT NULL,
    worksheet_id TEXT NOT NULL,
    disposition TEXT CHECK (disposition IN (
        'ESCALATE_STR_REVIEW', 'CLOSE_BENIGN', 'INSUFFICIENT_DATA', 'REJECTED',
        'escalate_str', 'close_benign', 'request_info', 'rejected'
    )),
    worksheet_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    approver_id TEXT NOT NULL,
    committed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('analyst', 'senior_reviewer', 'admin')),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti TEXT PRIMARY KEY,
    revoked_by TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    revoked_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS investigation_events (
    event_id BIGSERIAL PRIMARY KEY,
    thread_id TEXT NOT NULL,
    event TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approval_tokens (
    token_id TEXT PRIMARY KEY,
    thread_id TEXT NOT NULL,
    worksheet_id TEXT NOT NULL,
    worksheet_sha256 TEXT NOT NULL,
    hmac_token TEXT NOT NULL,
    issued_to TEXT NOT NULL DEFAULT 'reviewer',
    issued_at TEXT NOT NULL,
    expires_at TEXT,
    consumed_at TEXT,
    consumed_by TEXT
);

CREATE TABLE IF NOT EXISTS audit_logs (
    log_id BIGSERIAL PRIMARY KEY,
    case_id TEXT,
    thread_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    payload_hash TEXT,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS thread_checkpoints (
    thread_id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    current_node TEXT NOT NULL,
    status TEXT NOT NULL,
    worksheet_id TEXT,
    payload_hash TEXT,
    state_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entity_profiles (
    customer_id TEXT PRIMARY KEY,
    profile_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_episodes (
    episode_id BIGSERIAL PRIMARY KEY,
    customer_id TEXT NOT NULL,
    episode_json TEXT NOT NULL,
    archived_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reflexion_playbook (
    lesson_id TEXT PRIMARY KEY,
    trigger_precondition TEXT NOT NULL,
    observed_failure TEXT NOT NULL,
    actionable_rule TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    reviewer_rationale TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS system_flags (
    flag_key TEXT PRIMARY KEY,
    flag_value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_txn_from ON transactions(from_account_id, txn_timestamp);
CREATE INDEX IF NOT EXISTS idx_txn_to ON transactions(to_account_id, txn_timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_thread ON audit_logs(thread_id);
CREATE INDEX IF NOT EXISTS idx_episodes_cust ON case_episodes(customer_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_worksheet_thread_revision ON worksheets(thread_id, revision) WHERE thread_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_approval_worksheet ON approval_tokens(worksheet_id);
CREATE INDEX IF NOT EXISTS idx_events_thread ON investigation_events(thread_id, event_id);

-- Privilege-separated PostgreSQL roles enforced by bank-records (RO) and case-actions (scoped writer)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auditguard_ro') THEN
        CREATE ROLE auditguard_ro NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auditguard_case_writer') THEN
        CREATE ROLE auditguard_case_writer NOLOGIN;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO auditguard_ro, auditguard_case_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO auditguard_ro, auditguard_case_writer;
GRANT INSERT, UPDATE ON worksheets, approval_tokens, cases, audit_logs TO auditguard_case_writer;
GRANT USAGE, SELECT ON SEQUENCE audit_logs_log_id_seq TO auditguard_case_writer;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO auditguard_ro, auditguard_case_writer;
GRANT auditguard_ro, auditguard_case_writer TO CURRENT_USER;
-- Credential tables (audit AG-33). This file is re-applied on every owner start-up (`postgres_ddl()`), so the
-- REVOKEs must live here, after the blanket GRANT above. Password hashes are readable by neither service role;
-- `revoked_tokens` (token ids + expiry only) stays readable by auditguard_ro, which the API's own read-only
-- connections use for the logout-revocation check.
REVOKE ALL ON users FROM auditguard_ro, auditguard_case_writer;
REVOKE ALL ON revoked_tokens FROM auditguard_case_writer;
