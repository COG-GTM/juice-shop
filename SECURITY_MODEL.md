# Threat model: COG-GTM/juice-shop

Built from the code, the repo's own `threat-model.json` (OWASP Threat Dragon "High Level Data Flow" diagram by Björn Kimminich) and `SECURITY.md`. Owner answers (Colin Imaizumi) are folded in as they arrive. Anything marked *(assumption)* is my reading of the code, not something the owner confirmed. Assumptions do not move any finding's priority.

## 1. System overview

OWASP Juice Shop (v20.x) is an intentionally vulnerable online shop used for security training, CTFs, awareness demos and as a target for security tools. A single Node.js/Express process (`server.ts`, `app.ts`) serves all of these:
- the Angular SPA (`frontend/`)
- the finale/Sequelize auto-generated REST API (`/api/*`)
- custom routes (`/rest/*`, `routes/*.ts`)
- the B2B order API (`/b2b/v2`)
- static directory listings (`/ftp`, `/encryptionkeys`, `/support/logs`, `/.well-known`)
- Swagger (`/api-docs`)
- Prometheus `/metrics`
- a Socket.io channel for challenge notifications

`SECURITY.md` draws the project's own line. A vulnerability that **is part of a hacking challenge** is a feature: there are 112 challenges in `data/static/challenges.yml`, the vulnerable lines are marked with `vuln-code-snippet` comments, and 152 fix options live in `data/static/codefixes/`. A vulnerability that is **not** part of any challenge is a real zero-day and goes to the maintainer.

## 2. Components

| Component | Code it covers |
|---|---|
| **Frontend** | `frontend/src/**` (Angular SPA: login, basket, score board, chatbot UI, web3 sandbox, admin/accounting pages) |
| **REST API** | `server.ts` routing, `routes/**` (except those listed below), `models/**`, finale auto-generated `/api/*` CRUD |
| **Authentication** | `lib/insecurity.ts` (RS256 JWT sign/verify, `isAuthorized`, `denyAll`, `appendUserId`, `isAccounting`, `isDeluxe`, md5 password hash, HMAC), `routes/login.ts`, `routes/2fa.ts`, `routes/resetPassword.ts`, `routes/changePassword.ts`, `routes/securityQuestion.ts`, OAuth (`frontend/src/app/oauth`) |
| **B2B API** | `routes/b2bOrder.ts` (`/b2b/v2/orders`, `notevil` inside `vm`) |
| **File Handling** | `routes/fileUpload.ts` (zip/XML/YAML parsing), `routes/profileImage*Upload.ts`, `routes/memory.ts`, `routes/fileServer.ts`, `routes/keyServer.ts`, `routes/logfileServer.ts`, `routes/quarantineServer.ts`, `ftp/`, `encryptionkeys/`, `uploads/` |
| **Data Stores** | `data/**` (seeding, `datacache`, MarsDB `data/mongodb.ts`), SQLite via Sequelize, local file system |
| **Challenge Engine** | `routes/verify.ts`, `lib/challengeUtils.ts`, `lib/antiCheat.ts`, `lib/codingChallenges.ts`, `routes/continueCode.ts`, `routes/restoreProgress.ts`, `routes/vulnCode*.ts`, `lib/startup/**`, `config/*.yml`, CTF flag generation (`ctf.key`) |
| **Integrations** | `routes/chat.ts` (JuicyBot, OpenAI-compatible LLM at `chatBot.llmApiUrl`, default `http://localhost:11434/v1`), `routes/web3Wallet.ts`, `routes/checkKeys.ts`, `routes/nftMint.ts`, Socket.io (`lib/startup/registerWebsocketEvents.ts`), `lib/webhook.ts` |
| **Build & Deploy** | `Dockerfile` (node build -> distroless, non-root UID 65532), `.github/workflows/**`, `package.json` dependencies, `docker-compose.test.yml`, `vagrant/`, `app.json` (Heroku), `.agents/**` |

Component names match the earlier juice-shop threat models in this org, so findings from different scans line up.

## 3. Trust boundaries (from `threat-model.json`)

1. **Browser <-> Application Server**: every actor in the diagram (B2C Customer, B2B Customer, Admin, Accounting) talks to the same Express process. There is no separate admin plane.
2. **Application Server <-> data stores**:
   - SQLite: users, baskets, cards, addresses, orders, products
   - MarsDB: reviews, orders
   - local file system: invoices, logs, uploads, configuration
3. **Application Server <-> external services**:
   - Google OAuth2 (marked `outOfScope` in the diagram)
   - the chatbot LLM endpoint
   - Web3/Ethereum RPC
   - the optional solved-challenge webhook
4. **In-process sandboxes**: `vm.runInContext` around `notevil` (B2B orders), plus libxml XML and js-yaml parsing in `routes/fileUpload.ts`. These are the only barrier between request data and the Node process. `challenges.safetyMode: auto` (`config/default.yml`, `lib/utils.ts`) disables the "Danger Zone" RCE challenges on Docker, Heroku and Gitpod.
5. **Container**: distroless image, runs as non-root, port 3000.

## 4. Entry points and who can reach them

- **Anonymous**:
  - auth: `/rest/user/login`, `/api/Users` (register), `/rest/user/reset-password`
  - shop: `/rest/products/search`, `/rest/track-order/:id`
  - integrations: `/rest/chat`, `/rest/web3/*`
  - listings and docs: `/ftp`, `/encryptionkeys`, `/support/logs`, `/api-docs`, `/metrics`, `/.well-known`
  - config and progress: `/rest/admin/application-configuration`, `/rest/continue-code*`
- **Any authenticated user** (JWT via `security.isAuthorized()` / `appendUserId()`):
  - shopping and payment: basket, cards, addresses, wallet, orders, deluxe membership
  - user content: reviews, complaints, privacy requests, data export
  - uploads: file and profile-image upload
  - `/b2b/v2`
- **Accounting role** (`isAccounting`): order history, delivery status, `/api/Quantitys/:id`.
- **Admin role**: administration page, user listing.
- `denyAll()` guards endpoints that are meant to be unreachable.

## 5. Assets and sensitivity *(assumption until the owner picks)*

- **The host**: RCE or sandbox escape (`vm`/`notevil`, libxml, js-yaml), file-system write, and hard-coded secrets in `lib/insecurity.ts`: the RSA JWT signing key, the HMAC secret, cookie secret, `ctf.key`, `encryptionkeys/*`.
- **Privileged access**: the admin and accounting roles.
- **Payment, card and wallet data**: `/api/Cards`, `/rest/wallet/balance`, orders, coupons.
- **Customer credentials and PII**: md5 password hashes, emails, addresses, security answers, data export.
- **Score board progress, continue codes and CTF flags**.

## 6. Attacker profiles *(assumption until the owner answers)*

- **Anonymous internet attacker**: reaches every anonymous entry point in section 4.
- **Registered customer**: self-registration is open, so anyone can become one, then try to escalate to other customers, admin or accounting.
- **Supply-chain attacker**: via npm dependencies (deliberately old ones such as `express-jwt` 0.1.3 and `jsonwebtoken` 0.4.0), CI workflows or `.agents/` skill files.

## 7. Existing controls

- Helmet `noSniff` and `frameguard`. CORS is fully open (`cors()` in `server.ts`).
- RS256 JWTs with a 6h expiry.
- Rate limit on password reset. Captcha on feedback and data export. Optional TOTP 2FA.
- `vm` sandboxes with timeouts. Safety mode for RCE challenges in containers.
- Distroless, non-root container image.

## 8. Out of scope / accepted risk

- Google OAuth2 provider (`outOfScope: true` in `threat-model.json`).
- Intentional challenge vulnerabilities: **pending the owner's answer**. Until then they keep the scanner's severity.
- `i18n/` (managed in Crowdin) *(assumption)*.

## 9. Infrastructure

No infrastructure repository was found for juice-shop: no Terraform, K8s or Helm. The deployment is described only by `Dockerfile`, `app.json` and `vagrant/`. Network exposure is therefore unknown (see open questions).

## 10. Finding tags

`OWASP Top 10` (2021 category), `CWE`, `CVE` (dependency findings) *(proposed, pending the owner)*.

## 11. Open questions

- Should challenge vulnerabilities be ranked as real flaws, or treated as accepted risk?
- Is the instance publicly reachable, internal only, or a CTF/training target?
- Which assets in section 5 matter most?
- Is there an infra repo, or anything in front of port 3000 (TLS, WAF, IP allow-list)?
