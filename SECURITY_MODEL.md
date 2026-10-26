# Threat model: COG-GTM/juice-shop

*Status: v2. It is built from the code, the repository's own `threat-model.json` (OWASP Threat Dragon, "High Level Data Flow") and `SECURITY.md`, plus the owner's answers (2026-10-26) in section 8.*

## 1. System overview
OWASP Juice Shop is an **intentionally vulnerable** web shop used for security training, CTFs and tool demos. It is a single Node.js/Express process (`server.ts`, `app.ts`) that serves an Angular SPA (`frontend/`), a REST API and a Sequelize auto-generated CRUD API (`/api/*`), and stores data in SQLite (`models/`) and MarsDB (in-memory NoSQL: reviews, orders). It runs as one container (`Dockerfile`: distroless nodejs24, UID 65532, port 3000). This repo holds no infrastructure-as-code, and I found no infrastructure repository.

`SECURITY.md` states the governing policy: vulnerabilities that belong to a hacking challenge are **intended**. Only vulnerabilities that are **not** part of any challenge are real (unwanted "zero days"). There are about 112 challenges in `data/static/challenges.yml`. Their vulnerable lines are marked inline with `// vuln-code-snippet` comments (33 snippets), and the intended fixes are in `data/static/codefixes/` (152 files).

## 2. Components
| Name | Covers | Notes |
|---|---|---|
| **Web client** | `frontend/` | Angular SPA, served statically from `frontend/dist/frontend`. DOM XSS, client-side challenges, Web3 wallet UI. |
| **API server** | `server.ts`, `app.ts`, `routes/` (except the auth, file, chatbot/Web3 and challenge routes listed below), `lib/utils.ts`, `views/`, `swagger.yml` | Express routing, the auto-generated Sequelize REST API under `/api/*`, shop features (basket, orders, payment, wallet, deluxe, reviews, complaints, recycles, B2B `/b2b/v2/orders`), metrics, redirects, video. |
| **Authentication** | `lib/insecurity.ts`, `routes/login.ts`, `routes/2fa.ts`, `routes/resetPassword.ts`, `routes/changePassword.ts`, `routes/securityQuestion.ts`, `routes/currentUser.ts`, `routes/authenticatedUsers.ts`, `routes/updateUserProfile.ts`, `frontend/src/app/oauth` | RS256 JWT, with the private key hard-coded in `lib/insecurity.ts`. `isAuthorized`, `denyAll`, `isAccounting`, `isDeluxe`, `appendUserId`. MD5 password hashes, TOTP 2FA, security questions, Google OAuth (out of scope in the Threat Dragon model). |
| **Data stores** | `models/`, `data/datacreator.ts`, `data/static/*.yml` (users, products, etc.), `data/mongodb.ts` | SQLite via Sequelize plus MarsDB. Seeded users include admin, accounting and deluxe roles. |
| **File handling** | `routes/fileUpload.ts`, `routes/profileImage*Upload.ts`, `routes/memory.ts`, `routes/fileServer.ts`, `routes/quarantineServer.ts`, `routes/keyServer.ts`, `routes/logfileServer.ts`, `routes/dataExport.ts`, `ftp/`, `uploads/`, `encryptionkeys/`, `logs/` | Zip, XML and YAML upload parsing, image URL fetch (SSRF), `/ftp` and `/support/logs` directory listings, `/encryptionkeys` exposure. |
| **Chatbot & Web3** | `routes/chat.ts`, `routes/web3Wallet.ts`, `routes/nftMint.ts`, `routes/checkKeys.ts`, `frontend/src/app/{chatbot,web3-sandbox,wallet-web3,nft-unlock,faucet}` | LLM chatbot (JuicyBot) via an OpenAI-compatible API (`LLM_API_KEY`), and Sepolia/Alchemy blockchain listeners (`ALCHEMY_API_KEY`). |
| **Challenge engine** | `lib/challengeUtils.ts`, `lib/antiCheat.ts`, `lib/codingChallenges.ts`, `lib/webhook.ts`, `lib/startup/`, `routes/verify.ts`, `routes/vulnCodeSnippet.ts`, `routes/vulnCodeFixes.ts`, `routes/continueCode.ts`, `routes/restoreProgress.ts`, `data/static/challenges.yml`, `data/static/codefixes/`, `rsn/`, `config/` | Solve detection, score board, continue codes (hashids), CTF flags (`ctf.key`, `CTF_KEY`), `safetyMode` (disables Danger Zone RCE challenges on Docker/Heroku when set to `auto`). |
| **Build & CI** | `Dockerfile`, `.github/workflows/`, `test/`, `cypress/`, `Gruntfile.js`, `package.json`, `frontend/package.json` | Supply chain, CI secrets, test fixtures. |

## 3. Trust boundaries & entry points
From `threat-model.json`, the boundaries are: browser to Angular frontend, frontend to application server, application server to its data stores (SQLite, MarsDB, local file system), and the external Google OAuth (out of scope).
- **Unauthenticated, internet-facing:** the whole app on port 3000. That includes `/rest/user/login`, registration (`POST /api/Users`), `/rest/products/search`, `/rest/track-order/:id`, `/rest/chat`, `/redirect`, `/ftp`, `/support/logs`, `/encryptionkeys`, `/api-docs`, `/metrics`, `/file-upload`, `/profile/image/url`, `/rest/web3/*`, and the static `.well-known` and `security.txt`.
- **Authenticated customer** (`security.isAuthorized()` / `appendUserId()`): basket, cards, addresses, wallet, orders, reviews, complaints, privacy requests, data export, 2FA, B2B orders (`/b2b/v2`).
- **Privileged roles:** `accounting` (`isAccounting()`: all orders, delivery status, quantities), `admin` (administration UI and `/api/Users`), `deluxe`.
- **Outbound:** the LLM API, Alchemy/Sepolia, the image-URL fetch, and an optional `SOLUTIONS_WEBHOOK`.

## 4. Assets
- User accounts: credentials (MD5 hashes), JWTs, security answers, TOTP secrets.
- PII and payment data: addresses, stored cards, wallet balances, orders, data exports.
- The host and container: the file system, `encryptionkeys/` (JWT public key, premium key), `ctf.key`, environment secrets (`LLM_API_KEY`, `ALCHEMY_API_KEY`, `CTF_KEY`). The JWT **private** key is hard-coded in source on purpose.
- Challenge integrity: the score board, CTF flags, continue codes, anti-cheat.
- Availability of a shared training instance.

**Most critical (owner):** user credentials, sessions (JWTs) and PII.

## 5. Attacker profiles
- **A1:** unauthenticated internet user.
- **A2:** self-registered customer.
- **A3:** privileged insider (accounting, admin, deluxe).
- **A4:** supply chain / CI attacker (dependencies, workflows).
- **A5:** a training participant cheating the score board. This one is specific to Juice Shop.

**In scope (owner):** only **A1, the unauthenticated internet attacker**. Findings that need a customer account (A2), a privileged role (A3), supply-chain access (A4) or score-board cheating (A5) are lowered.

## 6. Existing controls
Helmet `noSniff` and `frameguard`, plus a feature policy (`server.ts`, around line 186). `helmet.xssFilter` is commented out on purpose. There is a rate limit on `/rest/user/reset-password`. RS256 JWT verification uses `express-jwt`. `denyAll()` blocks dangerous CRUD verbs. The container runs as non-root on a distroless image. `safetyMode: auto` (`config/default.yml`) disables Danger Zone challenges on Docker and Heroku. Startup validators are in `lib/startup/` (`validateConfig`, `validatePreconditions`, `restoreOverwrittenFilesWithOriginals`).

## 7. Out of scope / accepted risk
- **Intentional challenge vulnerabilities (owner, per `SECURITY.md`):** accepted risk. A finding whose root cause is a hacking challenge (a `vuln-code-snippet` vuln-line, or a vulnerability listed in `data/static/challenges.yml` / `data/static/codefixes/`) is lowered to `none`. Only non-challenge (unintended) vulnerabilities matter.
- **Web3 / blockchain sandbox and NFT challenges (owner):** out of scope. This covers `routes/web3Wallet.ts`, `routes/nftMint.ts`, `routes/checkKeys.ts`, `/rest/web3/*` and `frontend/src/app/{web3-sandbox,wallet-web3,nft-unlock,faucet}`. The JuicyBot chatbot stays in scope.
- **Per `threat-model.json`:** the Google OAuth provider is out of scope.
- **Infrastructure (owner):** there is no infrastructure repository. The app runs from the `Dockerfile` only.

## 8. Owner answers (2026-10-26)
- Q1, challenge vulnerabilities: treat them as accepted risk and lower them. Only non-challenge issues matter.
- Q2, attackers: only the unauthenticated internet attacker.
- Q3, out of scope: the Web3 / blockchain sandbox and the NFT challenges.
- Q4, critical assets: user credentials, sessions and PII.
- Q5, infrastructure: there is no infrastructure repository (Dockerfile only).

## 9. Open questions
- None outstanding.
