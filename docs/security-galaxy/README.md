# Semantic Galaxy — Juice Shop security overlay

`juice-shop-semantic-galaxy.html` is a single self-contained page (no build step, no
network access, no dependencies) that maps this repository as a pseudo-3D graph and
overlays the intentional vulnerabilities that live in it.

Open it directly in a browser:

```
open docs/security-galaxy/juice-shop-semantic-galaxy.html
```

## What it shows

- **Subsystems** — 11 clusters (server bootstrap, security primitives, auth & identity,
  user & privacy, catalog & reviews, basket & checkout, file handling, integrations,
  challenge & scoring, data layer, Angular SPA) expanded into 68 nodes, each bound to
  the real files it represents.
- **Relations** — cross-cluster edges for the request paths that matter (routing,
  token verification, model access, scoring hooks).
- **Security heat** — 57 findings, attributed to nodes by file path and rolled up the
  tree with severity weights (critical 8, high 4, medium 2, low 1), so a cluster glows
  in proportion to the risk it contains.
- **Attack chain** — an animated five-step, four-file path: the served public key and
  the committed RSA private key make token forgery possible, `jwtFrom()` takes caller
  identity from a request header, `isAccounting()` reads the role out of that same
  token, and `allOrders()` then returns every order in the shop. Press `c` to play it.
- **Detail panel** — click any node for its description, files and findings
  (severity, CWE, the vulnerable line, and how the flaw is reached).

Controls: drag to orbit, wheel to zoom, click to focus, `Esc` to reset, `r` to replay
the scan, `c` to toggle the chain. Buttons toggle heat, labels, dark theme and a
hypothetical "preview PR fixes" mode that shows the galaxy as it would look with every
finding remediated.

## Data provenance

Every finding cites a path and a line number that existed in the source tree when this
page was generated, together with the vulnerable line itself. The findings describe
Juice Shop's **existing, deliberate** vulnerabilities — nothing here changes application
behaviour, and the page contains no exploit payloads. Dependency/CVE findings, tests,
Cypress specs and `data/static/codefixes/` are intentionally out of scope.

Line numbers drift as the code evolves; treat the citations as a snapshot rather than a
live index.
