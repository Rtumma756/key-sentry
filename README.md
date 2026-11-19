# KeySentry — AI API Leaked-Key Scanner

Paste code, find leaked AI API keys, fix them.

**Everything runs client-side in the browser, except the optional
encrypted vault (see below).** Pasted code and scanned files never leave
your machine. The only network calls the app makes are the optional
public GitHub repo scan (public GitHub API, unauthenticated) and a
finding you explicitly choose to store in the vault.

## Encrypted vault (admin-only unmask)

The vault is where a finding's **unmasked** key lives — encrypted at rest
in Vercel Postgres (free tier), admin-only to open. Everything else (this
page, copied reports, the audit log) shows masked keys only. It exists so
a business scanning its **own** code can keep a leaked key on file long
enough to rotate it.

**Setup** (free tier only — nothing here costs money):

1. In Vercel: Storage → Create → Postgres (free tier) for this project.
2. Set two environment variables (Settings → Environment Variables):
   - `VAULT_ENCRYPTION_KEY` — generate with `openssl rand -base64 32`
     (base64 of 32 random bytes; AES-256-GCM key).
   - `VAULT_ADMIN_PASS` — the admin passphrase for reveals/rotates.
3. Redeploy. Tables (`vault_entries`, `vault_audit`) are created
   automatically on first use.

Until all three are in place, the vault section shows exactly what is
missing and every vault route answers `503 Vault is not configured` —
it never fails open.

**How it works**

- **Store** — a “Store in vault” button on each finding. That click is the
  explicit consent: it is the only way a full key leaves the browser.
  The server re-computes the masked value and fingerprint from the key,
  encrypts it with AES-256-GCM (fresh 12-byte nonce per entry), and stores
  ciphertext only. Nothing is stored automatically.
- **List** — masked entries only; needs no passphrase.
- **Reveal** — admin passphrase required; the full key is shown once and
  the reveal is audit-logged (who/when/which finding — never the key).
- **Rotate** — admin passphrase required; marks an entry rotated after
  the key has been rotated at the provider.
- **Audit trail** — append-only log of every store / reveal / rotate.

**Scope boundary (enforced in the UI)** — vault only keys from scans you
ran yourself (pasted code, or your own repo) so you can rotate them.
Never vault keys found in other people's public code; the repo-scan store
button is offered per finding and only on your explicit click. Demo
TESTFAKE keys are fine to vault for a trial run.

## Quickstart

```bash
npm install
npm run dev     # http://localhost:3000
npm run build   # production build
```

## What it does

- **Paste-to-scan** — paste source code, a `.env` file, or a config file and
  scan it in the browser. Findings show provider, credential type, line
  number, a masked key (first 4 … rest hidden — the full key is never shown),
  severity, and the context line with the key masked.
- **Demo mode** — one click loads sample code with planted FAKE keys
  (TESTFAKE markers) plus decoys that must not be flagged. Expected result:
  16 findings, 0 decoy hits.
- **Metrics panel** — lines/bytes scanned, candidates found, findings after
  dedup, breakdown by provider and credential type, scan time. The accuracy
  box quotes the CLI prototype's fixture scorecard: 16 of 16 planted keys
  found, 0 false positives on the decoy set.
- **Remediation** — every finding has an expandable checklist (revoke at the
  provider console, rotate, scrub git history, move to env vars, add to
  `.gitignore`, enable push protection) and a "Copy remediation report"
  button that copies a Markdown summary (masked keys only).
- **Public repo scan** — enter a public `github.com/owner/repo` URL. The app
  fetches the file tree via the public GitHub API and scans up to 25 small
  text files (max 200 KB each) in the browser. Unauthenticated GitHub API
  use is limited to 60 requests/hour, and large repos return a truncated
  tree — the scan reports what it could fetch.
- **Feedback** — a visible section linking to GitHub Issues and listing the
  most useful feedback (missed detections, false positives, providers to
  add).

## Detectors

Ported from the CLI prototype in `~/workspace/ai-key-scanner`
(`detectors/registry.py`, `detectors/entropy.py`): 15 detectors across 13
providers — OpenAI (project, service account, legacy), Anthropic, Google
Gemini, Groq, OpenRouter, DeepSeek, xAI, Perplexity, Hugging Face,
Replicate, Together AI, Mistral, Cohere — plus a Shannon-entropy fallback
(threshold 4.5) for generic `api_key|token|secret` assignments. Same
patterns, same ordering, same overlap resolution, same placeholder rules
(regex matches are always kept; placeholder words only gate the entropy
fallback). Adding a provider is one entry in `lib/detectors.ts`.

## Privacy and safety

- No API keys, secrets, or credentials anywhere in the code.
- Scanning is client-side. The only server-side routes are the vault
  (`/api/vault/*`): they handle a finding only when you explicitly click
  “Store in vault”, and they store ciphertext only.
- Keys are masked everywhere: on screen, in copied output, and in reports.
  A runtime rule: the full credential value is never rendered — except a
  vault reveal, which shows it once to an admin and audit-logs the reveal.
- The app never validates keys against provider APIs (no "is this key live"
  check) — that only happens in the CLI prototype with an explicit flag, for
  keys the user owns.

## Limits

- Paste/repo scans only see the text you provide — a clean result does not
  prove a codebase is clean (git history, other branches, and other files
  are not covered here; the CLI prototype covers git history).
- The public GitHub API is rate-limited to 60 requests/hour without a
  token, and repo scans are capped at 25 files / 200 KB each.
- Entropy-based detection can miss unusual formats and can flag unusual
  high-entropy strings; treat findings as "revoke first, ask questions
  later."

## Stack

Next.js 16 + TypeScript (App Router), plain CSS, no dependencies beyond
Next.js/React defaults.
