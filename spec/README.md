# Specs

Feature specs, worked in numeric order — 1 spec = 1 branch = 1 PR.
Format per spec: Context · User Stories · Functional Requirements (FR-N) ·
Data Model / Routes / UI · Acceptance Criteria (Given/When/Then) · Test list ·
Out of Scope.

| #    | Spec               | Scope                                                     |
| ---- | ------------------ | --------------------------------------------------------- |
| 0001 | foundation         | App skeleton, config, DB/migrations, /healthz, CLI, CI    |
| 0002 | crypto-secrets     | Master key, optional passphrase KEK, secret sealing       |
| 0003 | auth-users         | First-run setup, roles, sessions, CSRF                    |
| 0004 | ca-core            | Create root+intermediate wizard, CA import, CA info       |
| 0005 | issue-sign         | Direct issuance (server keygen) + CSR signing, UI + REST  |
| 0006 | inventory-download | Certificate inventory, search, PEM/PKCS#12 export         |
| 0007 | revoke-crl         | Revocation, CRL build/serve, CDP extension                |
| 0008 | api-tokens         | API token auth, OpenAPI polish                            |
| 0009 | audit              | Audit log                                                 |
| 0010 | acme-core          | Directory, nonces, accounts, JWS middleware, orders/authz |
| 0011 | acme-challenges    | http-01, dns-01, tls-alpn-01 validators                   |
| 0012 | acme-finalize-eab  | finalize/cert/revokeCert, EAB                             |
| 0013 | mcp                | FastMCP mount + tools                                     |
| 0014 | deployment         | Dockerfile, compose, Unraid template, release workflows   |
