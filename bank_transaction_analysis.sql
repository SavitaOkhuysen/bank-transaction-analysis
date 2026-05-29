-- ============================================================
-- Banking Transaction Anomaly Detection
-- Author: Savita Okhuysen
-- Dataset: Bank Transaction Dataset (Kaggle)
-- Database: PostgreSQL 18
-- Description: SQL analysis identifying suspicious transaction
-- patterns using behavioral baselines, z-score anomaly
-- detection, login risk scoring, and shared IP fraud detection.
-- ============================================================

-- ============================================================
-- SETUP: Create table and import data
-- ============================================================

CREATE TABLE transactions (
    transaction_id VARCHAR(10) PRIMARY KEY,
    account_id VARCHAR(10),
    transaction_amount NUMERIC(10,2),
    transaction_date TIMESTAMP,
    transaction_type VARCHAR(10),
    location VARCHAR(50),
    device_id VARCHAR(10),
    ip_address VARCHAR(20),
    merchant_id VARCHAR(10),
    channel VARCHAR(10),
    customer_age INTEGER,
    customer_occupation VARCHAR(20),
    transaction_duration INTEGER,
    login_attempts INTEGER,
    account_balance NUMERIC(10,2),
    previous_transaction_date TIMESTAMP
);

-- \COPY transactions FROM 'your/path/to/bank_transactions_data_2.csv' WITH (FORMAT csv, HEADER true);

-- ============================================================
-- QUERY 1: Dataset Overview
-- What: High-level summary of transaction volume, amounts,
-- and initial suspicious login count across all accounts.
-- Why: Establishes baseline metrics before deeper analysis.
-- Finding: 122 of 2,512 transactions (4.9%) show multiple
-- login attempts, flagging them for further investigation.
-- ============================================================

SELECT
    COUNT(*) as total_transactions,
    ROUND(AVG(transaction_amount),2) as avg_transaction,
    ROUND(MIN(transaction_amount),2) as min_transaction,
    ROUND(MAX(transaction_amount),2) as max_transaction,
    SUM(CASE WHEN login_attempts > 1 THEN 1 ELSE 0 END) as suspicious_login_count
FROM transactions;

-- ============================================================
-- QUERY 2: High Risk Transactions by Login Attempts
-- What: Flags transactions with multiple login attempts,
-- calculates each transaction as a percentage of account
-- balance, and assigns a login risk tier.
-- Why: Multiple failed logins before a transaction is a
-- classic account takeover signal. Combining with balance
-- percentage reveals transactions that could drain an account.
-- Finding: TX000275 shows 5 login attempts on a $323 balance
-- account with a $1,176 transaction — 363% of balance.
-- TX000148 shows $514 on a $421 balance (122%) with 5 attempts.
-- ============================================================

SELECT
    transaction_id,
    account_id,
    transaction_amount,
    login_attempts,
    channel,
    account_balance,
    ROUND((transaction_amount / account_balance * 100),2) as pct_of_balance,
    CASE
        WHEN login_attempts > 2 THEN 'High'
        WHEN login_attempts = 2 THEN 'Medium'
        ELSE 'Low'
    END as login_risk
FROM transactions
WHERE login_attempts > 1
ORDER BY login_attempts DESC, transaction_amount DESC
LIMIT 20;

-- ============================================================
-- QUERY 3: Account Behavior Baseline (Window Functions)
-- What: For each transaction, shows the previous transaction
-- amount for the same account, the change between them, total
-- transactions per account, and that account's average amount.
-- Why: Isolating each transaction against its own account
-- history reveals erratic patterns invisible in aggregate.
-- Finding: AC00002 shows a $477 first transaction followed
-- immediately by $59 — a -$417 drop — consistent with account
-- takeover where a fraudster makes one large withdrawal then
-- tests the account with smaller transactions.
-- ============================================================

SELECT
    account_id,
    transaction_id,
    transaction_amount,
    transaction_date,
    LAG(transaction_amount) OVER (PARTITION BY account_id ORDER BY transaction_date) as prev_transaction_amount,
    ROUND(transaction_amount - LAG(transaction_amount) OVER (PARTITION BY account_id ORDER BY transaction_date), 2) as amount_change,
    COUNT(*) OVER (PARTITION BY account_id) as total_account_transactions,
    ROUND(AVG(transaction_amount) OVER (PARTITION BY account_id), 2) as account_avg_amount
FROM transactions
ORDER BY account_id, transaction_date
LIMIT 20;

-- ============================================================
-- QUERY 4: Z-Score Anomaly Detection
-- What: Calculates how many standard deviations each
-- transaction is above that account's own average spend.
-- Uses two CTEs: one to build per-account stats, one to
-- score each transaction against those stats.
-- Why: A $500 transaction may be normal for one customer
-- but extreme for another. Z-score normalizes for individual
-- spending behavior — the foundation of behavioral analytics.
-- Finding: TX001214 (AC00170) has both a z-score of 2.25
-- AND 5 login attempts — two independent fraud signals on
-- the same transaction, the highest priority alert in the
-- dataset. TX001635 has the highest dollar amount at $1,762
-- (z-score 2.33) against an account average of $450.
-- ============================================================

WITH account_stats AS (
    SELECT
        account_id,
        ROUND(AVG(transaction_amount),2) as avg_amount,
        ROUND(STDDEV(transaction_amount),2) as stddev_amount,
        COUNT(*) as transaction_count
    FROM transactions
    GROUP BY account_id
),
flagged AS (
    SELECT
        t.transaction_id,
        t.account_id,
        t.transaction_amount,
        t.login_attempts,
        t.channel,
        t.location,
        a.avg_amount,
        a.stddev_amount,
        ROUND((t.transaction_amount - a.avg_amount) / NULLIF(a.stddev_amount, 0), 2) as z_score
    FROM transactions t
    JOIN account_stats a ON t.account_id = a.account_id
)
SELECT *
FROM flagged
WHERE z_score > 2
ORDER BY z_score DESC
LIMIT 20;

-- ============================================================
-- QUERY 5: Shared IP Fraud Network Detection
-- What: Identifies IP addresses used by more than one
-- account, then surfaces all transactions from those IPs
-- with total exposure per IP address.
-- Why: Legitimate customers don't share IP addresses.
-- Multiple accounts transacting from the same IP is a strong
-- indicator of a fraud ring, account takeover operation,
-- or credential stuffing attack.
-- Finding: IP 200.136.146.93 was used by 13 different
-- accounts totaling $2,697 — the strongest network-level
-- fraud signal in the dataset. IP 49.31.186.82 shows 11
-- accounts with an escalating pattern: small test transactions
-- for 10 months followed by a $1,077 transaction in December,
-- consistent with fraud ring behavior.
-- ============================================================

WITH shared_ips AS (
    SELECT
        ip_address,
        COUNT(DISTINCT account_id) as account_count,
        COUNT(*) as transaction_count,
        ROUND(SUM(transaction_amount),2) as total_amount
    FROM transactions
    GROUP BY ip_address
    HAVING COUNT(DISTINCT account_id) > 1
)
SELECT
    t.ip_address,
    t.account_id,
    t.transaction_id,
    t.transaction_amount,
    t.transaction_date,
    t.channel,
    t.location,
    s.account_count,
    s.total_amount as ip_total_amount
FROM transactions t
JOIN shared_ips s ON t.ip_address = s.ip_address
ORDER BY s.account_count DESC, t.ip_address, t.transaction_date
LIMIT 25;

