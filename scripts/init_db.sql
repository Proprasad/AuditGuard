-- AuditGuard Canonical Relational Schema (PostgreSQL DDL)
-- Section 6.2 of Technical Implementation Blueprint

CREATE TABLE IF NOT EXISTS banks (
    bank_id VARCHAR(16) PRIMARY KEY,
    bank_name VARCHAR(120) NOT NULL,
    ifsc_prefix VARCHAR(8) NOT NULL
);

CREATE TABLE IF NOT EXISTS customers (
    customer_id VARCHAR(32) PRIMARY KEY,
    full_name VARCHAR(120) NOT NULL,
    synthetic_pan_hash VARCHAR(64) UNIQUE NOT NULL,
    kyc_tier VARCHAR(16) CHECK (kyc_tier IN ('FULL', 'MINIMAL', 'EXPIRED')),
    occupation VARCHAR(80) NOT NULL,
    declared_annual_income_inr NUMERIC(14,2) NOT NULL,
    risk_rating VARCHAR(16) CHECK (risk_rating IN ('LOW', 'MEDIUM', 'HIGH')),
    onboarding_date DATE NOT NULL,
    kyc_notes TEXT
);

CREATE TABLE IF NOT EXISTS commercial_registry (
    registry_id VARCHAR(32) PRIMARY KEY,
    customer_id VARCHAR(32) REFERENCES customers(customer_id),
    entity_type VARCHAR(32) CHECK (entity_type IN ('MARKETPLACE', 'EMPLOYER', 'NGO_80G', 'CHIT_FUND', 'MERCHANT')),
    registration_number VARCHAR(64) UNIQUE NOT NULL,
    status VARCHAR(16) CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED')),
    registered_since DATE NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    account_id VARCHAR(32) PRIMARY KEY,
    bank_id VARCHAR(16) REFERENCES banks(bank_id),
    customer_id VARCHAR(32) REFERENCES customers(customer_id),
    account_type VARCHAR(24) CHECK (account_type IN ('SAVINGS', 'CURRENT', 'ESCROW', 'SALARY')),
    status VARCHAR(16) CHECK (status IN ('ACTIVE', 'DORMANT', 'FROZEN')),
    opened_date DATE NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions (
    txn_id VARCHAR(32) PRIMARY KEY,
    from_account_id VARCHAR(32) REFERENCES accounts(account_id),
    to_account_id VARCHAR(32) REFERENCES accounts(account_id),
    amount_inr NUMERIC(14,2) NOT NULL CHECK (amount_inr > 0),
    txn_timestamp TIMESTAMPTZ NOT NULL,
    channel VARCHAR(16) CHECK (channel IN ('IMPS', 'NEFT', 'RTGS', 'UPI')),
    memo_text TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id VARCHAR(32) PRIMARY KEY,
    seed_account_id VARCHAR(32) REFERENCES accounts(account_id),
    triggered_at TIMESTAMPTZ NOT NULL,
    rule_triggered VARCHAR(64) NOT NULL,
    initial_amount_inr NUMERIC(14,2) NOT NULL,
    status VARCHAR(24) DEFAULT 'OPEN'
);

CREATE TABLE IF NOT EXISTS cases (
    case_id VARCHAR(32) PRIMARY KEY,
    alert_id VARCHAR(32) UNIQUE REFERENCES alerts(alert_id),
    disposition VARCHAR(32) CHECK (disposition IN ('ESCALATE_STR_REVIEW', 'CLOSE_BENIGN', 'INSUFFICIENT_DATA', 'REJECTED')),
    worksheet_json JSONB NOT NULL,
    payload_hash VARCHAR(80) NOT NULL,
    approver_id VARCHAR(64) NOT NULL,
    committed_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    log_id BIGSERIAL PRIMARY KEY,
    case_id VARCHAR(32),
    thread_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(48) NOT NULL,
    actor VARCHAR(64) NOT NULL,
    payload_hash VARCHAR(80),
    details_json JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_txn_from ON transactions(from_account_id, txn_timestamp);
CREATE INDEX IF NOT EXISTS idx_txn_to ON transactions(to_account_id, txn_timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_thread ON audit_logs(thread_id);
