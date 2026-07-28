<div align="center">

<pre>
    _   _                               _
  __ _ _   _| |_| |__        ___  ___ _ ____   _(_) ___ ___
 / _` | | | | __| '_ \_____ / __|/ _ \ '__\ \ / / |/ __/ _ \
| (_| | |_| | |_| | | |_____\__ \  __/ |   \ V /| | (_|  __/
 \__,_|\__,_|\__|_| |_|     |___/\___|_|    \_/ |_|\___\___|
</pre>

</div>

## Purpose

This document explains what we can do immediately using free/public resources, what we can estimate before client credentials are available, and what minimum privileged access is needed to validate production data access safely.

The goal is to prepare a credible PoC without overclaiming access to private client data.

## Executive Summary

| Question | Practical Answer |
|---|---|
| Can we build something now? | Yes. We can build connector shells, mock ingestion, response-format simulators, RAG/indexing demo, and an access-readiness checklist. |
| Can we fetch client data for free? | No. Client private data requires explicit authorization, credentials, and license coverage. |
| How much can we estimate using free resources? | Around 40-50% of technical PoC readiness. |
| Best next ask from client | Limited read-only Sedna credentials and Argus sample/trial/licensed feed access. |

## 1. What We Can Do Right Now With Free Resources

### API Documentation and Integration Research

We can review public documentation to understand:

- API authentication flow
- OAuth/client credential process
- Token handling
- Endpoint structure
- Expected request/response format
- Rate-limit and pagination expectations
- FTP/SFTP/API/Snowflake delivery options
- Licensing and AI/ML usage limitations

### Expected Response Format Preparation

We can prepare expected models for:

- Sedna messages
- Attachments
- Contacts
- Teams
- Users
- Events
- Category tags
- Job references
- Argus CSV/feed rows
- Price codes
- Product metadata
- Corrections and updates

### Auth Flow Preparation

| Source | What We Can Prepare Now |
|---|---|
| Sedna | OAuth client credential flow, bearer token usage, token refresh, request wrapper |
| Argus FTP/SFTP | Folder polling, file parsing, timestamp handling, correction upsert logic |
| Argus REST/SOAP | API client interface, error handling, entitlement checks |
| Argus Snowflake | Generic Snowflake shared-data ingestion pattern |
| Microsoft Graph fallback | Email/attachment response format simulator if Sedna API is blocked |

## 2. What We Can Estimate Before Client Access

| Area | Can Estimate? | Confidence |
|---|---:|---:|
| Auth method | Yes | High |
| Endpoint/delivery approach | Yes | Medium-High |
| Expected fields | Partial | Medium |
| Response format | Partial | Medium |
| Pagination/rate-limit behavior | Partial | Medium |
| Client data volume | No | Low |
| Sedna mailbox/team visibility | No | Low |
| Argus subscribed products | No | Low |
| AI/ML usage rights | No | Low |
| Production feasibility | Partial | Medium-Low |

## 3. PoC Components We Can Build Now

1. Datasource registry for Sedna, Argus FTP/API, Argus Snowflake, and optional Microsoft Graph fallback.
2. Mock connector layer using sample/synthetic payloads.
3. Ingestion pipeline for pull, validate, normalize, deduplicate, upsert, and log.
4. Schema mapping table.
5. RAG/indexing demo using mocked Sedna and Argus data.
6. Access-readiness dashboard showing missing credentials, scopes, and blockers.
7. Compliance gate for AI/ML usage rights.

## 4. More Free or Low-Friction Resources

### Sedna

We can use free/public Sedna resources to:

- Understand OAuth authentication.
- Prepare Postman/API collections.
- Build mock message retrieval.
- Understand Platform API use cases.
- Identify connected apps that may enrich data.
- Prepare the minimal access checklist.

### Argus

We can use free/public Argus resources to:

- Understand feed delivery patterns.
- Prepare CSV/feed parsers.
- Understand correction handling.
- Identify likely product families.
- Understand AI-Ready Data positioning.
- Prepare FTP/SFTP/API/Snowflake ingestion design.

## 5. Minimum Client Access Needed

### Sedna Minimum Access

Ask client for:

- Tenant base URL
- OAuth `client_id`
- OAuth `client_secret`
- Read-only scopes:
  - `MESSAGE_READ`
  - `EVENT_READ`
  - `CONTACT_READ`
  - `JOBREFERENCE_READ`
  - `CATEGORYTAG_READ`
  - `TEAM_READ`
  - `USER_READ`
  - `DOCUMENT_READ`, only if attachments are required
- Access to one test team/mailbox
- Sample message IDs or date range
- Confirmation that Platform API access is enabled

### Argus Minimum Access

Ask client for:

- Subscribed Argus product list
- Required product/price codes
- Confirmation that AI/ML/RAG usage is allowed
- Preferred delivery channel:
  - FTP/SFTP/FTPS
  - REST API
  - SOAP API
  - Snowflake
- Test/sample feed files
- API or feed credentials
- Delivery schedule and timezone
- Correction/update handling rules

## 6. Recommended PoC Plan

| Phase | Inputs | Output |
|---|---|---|
| Phase 1: Free-resource build | Public docs, synthetic payloads | Mock connector, schema, ingestion pipeline, RAG demo |
| Phase 2: Sample-data validation | Client sample files/exports | Parser validation and realistic field mapping |
| Phase 3: Read-only live probe | Minimal read-only credentials | Connectivity report and data-access validation |
| Phase 4: Production-readiness plan | License and security approval | Deployment and monitoring plan |

## 7. Client Access Request Template

To complete a controlled PoC, we request limited read-only access to validate integration feasibility.

For Sedna, please provide a tenant URL, OAuth client credentials with read-only scopes, and access to one test team/mailbox.

For Argus, please confirm subscribed products, AI/ML usage rights, and provide either sample feed files or temporary licensed FTP/API/Snowflake access.

We will not request write access for discovery. The initial probe can be limited to a small date range or sample dataset.

## 8. Risks and Guardrails

- Do not represent mocked testing as proof of client data access.
- Do not index Argus content for AI/RAG unless the license permits AI/ML usage.
- Do not request broad mailbox access for Sedna discovery.
- Start with one test mailbox/team only.
- Log all probe actions.
- Keep credentials in a secure vault.
- Separate technical access from legal usage rights.

## Final Position

A strong PoC can be started immediately using free resources, but it should be positioned as integration readiness, not full client-data validation.

The best next step is to build the mock connector and access-readiness checklist, then request minimal read-only access to validate real data shape, permissions, and legal usage rights.