# Product Info: SecurePay Gateway

## Overview

SecurePay Gateway is a cloud-hosted payment processing API that enables e-commerce merchants to accept credit card and ACH payments. It is deployed on AWS (EKS + RDS Aurora) and exposes RESTful endpoints consumed by merchant-side JavaScript SDKs and mobile apps (iOS/Android).

## Architecture

- **API Layer**: Python/FastAPI services behind an AWS Application Load Balancer. TLS 1.2+ enforced. API keys and OAuth 2.0 bearer tokens used for authentication.
- **Database**: Aurora PostgreSQL (encrypted at rest, AES-256). Stores transaction records, merchant credentials (hashed), and tokenised card data.
- **Card Tokenisation**: Raw PAN data is never stored. A third-party tokenisation vault (CardVault Inc.) stores card numbers and returns opaque tokens.
- **Admin Portal**: Internal-only React web app accessible via VPN. Used by operations staff to manage merchants, view transactions, and trigger refunds.
- **Webhook Delivery**: Outbound HTTPS webhooks notify merchants of payment events (success, failure, chargeback).
- **Logging & Monitoring**: CloudWatch Logs, Datadog APM, and AWS GuardDuty. Logs include request metadata but PII is redacted before storage.

## Key Data Flows

1. Cardholder → Merchant Website → SecurePay JS SDK → API Gateway
2. API Gateway → FastAPI → CardVault Inc. (tokenisation)
3. API Gateway → FastAPI → Aurora DB (transaction record write)
4. Aurora DB ← FastAPI ← Admin Portal (transaction lookups, refunds)
5. FastAPI → Merchant Webhook Endpoint (event notification)

## Actors

- **Cardholders**: End consumers submitting payment data via merchant checkout pages.
- **Merchants**: Businesses integrating the SecurePay SDK; issued API keys.
- **Operations Staff**: Internal users with admin portal access over VPN.
- **CardVault Inc.**: Third-party tokenisation provider; PCI DSS Level 1 certified.
- **AWS**: Cloud infrastructure provider.

## Compliance Requirements

- PCI DSS Level 1 (annual QSA audit)
- SOC 2 Type II
- GDPR (cardholder EU data)

## Known Constraints

- Merchants can register webhooks pointing to arbitrary URLs.
- API keys are long-lived (no automatic rotation today).
- Admin portal does not currently enforce MFA.
