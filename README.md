# Banking Transaction Anomaly Detection
**PostgreSQL | Window Functions | CTEs | Fraud Analytics**

## Overview
SQL analysis of 2,512 real banking transactions to identify suspicious patterns 
and potential fraud using behavioral baselines, statistical anomaly detection, 
and network-level fraud signals — techniques drawn from my fraud detection work 
at Bangor Savings Bank.

## Dataset
- **Source:** Bank Transaction Dataset (Kaggle)
- **Size:** 2,512 transactions across 500 accounts
- **Fields:** Transaction amount, channel, location, IP address, login attempts, 
account balance, customer demographics

## Key Findings

### 1. Dataset Overview
- 2,512 total transactions with an average value of $297.59
- Transaction amounts range from $0.26 to $1,919
- **122 transactions (4.9%)** show multiple login attempts — flagged for investigation
- Minimum transaction of $0.26 suggests test transaction activity

### 2. High Risk Login + Balance Analysis
- Identified transactions combining multiple login attempts with high 
percentage-of-balance withdrawals
- **TX000275:** 5 login attempts on a $323 balance account with a $1,176 
transaction — 363% of available balance
- **TX000148:** $514 transaction on a $421 balance (122%) with 5 login attempts 
via Online channel

### 3. Account Behavior Baseline (Window Functions)
- Used `LAG()` and `AVG() OVER()` window functions to compare each transaction 
against that account's own history
- **AC00002** shows a $477 opening transaction followed immediately by $59 
(a -$418 drop) — consistent with account takeover pattern where a fraudster 
makes one large withdrawal then tests the account with smaller transactions

### 4. Z-Score Anomaly Detection
- Calculated behavioral z-scores by comparing each transaction to that 
account's mean and standard deviation
- **TX001214 (AC00170):** z-score of 2.25 AND 5 login attempts — two 
independent fraud signals on the same transaction, the highest priority 
alert in the dataset
- **TX001635 (AC00358):** Highest dollar anomaly at $1,762 against an 
account average of $450 (z-score 2.33)
- 20 transactions exceed a z-score of 2.0, representing statistically 
unusual spending behavior

### 5. Shared IP Fraud Network Detection
- Identified IP addresses used by multiple distinct account holders — 
a strong indicator of fraud rings or account takeover operations
- **IP 200.136.146.93** used by **13 different accounts** totaling $2,697
- **IP 49.31.186.82** used by **11 different accounts** totaling $3,522, 
with an escalating pattern — small test transactions for 10 months 
followed by a $1,077 transaction in December

## SQL Techniques Used
- `CTEs` (Common Table Expressions) for readable, layered logic
- `Window functions` — LAG(), AVG() OVER(), COUNT() OVER() with PARTITION BY
- `Z-score calculation` using STDDEV() for behavioral anomaly detection
- `CASE` statements for risk tier classification
- `HAVING` clause for aggregate filtering
- `NULLIF()` to handle division by zero edge cases
- `Self-joins` via CTEs for network analysis

## How to Run
1. Install PostgreSQL
2. Create database: `CREATE DATABASE bank_transactions;`
3. Create table and import CSV using schema in `bank_transaction_analysis.sql`
4. Run queries sequentially — each builds on the previous findings

## Background
This project was built to demonstrate applied fraud detection analytics 
using SQL, drawing on experience as a Security Champion and customer 
analyst at Bangor Savings Bank where I developed Excel-based fraud 
detection workflows analyzing transactional patterns.
