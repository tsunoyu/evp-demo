# Email Verification Protocol (EVP) - Relying Party (RP) & Localhost Mock Issuer Demo

This repository contains both:
1. **A 100% Client-Side Relying Party (RP) & Friction Benchmark SPA** (`index.html`, `app.js`, `traditional.html`, `explainer.html`, `glossary.html`) ready for **GitHub Pages** deployment.
2. **A Zero-Dependency Node.js Localhost Verifier, RFC 9421 Mock Issuer, & Automated Test Suite** (`server.js`, `evp-core.js`, `test/evp.test.js`, and [`PARTNER_LOCALHOST_GUIDE.md`](PARTNER_LOCALHOST_GUIDE.md)) implementing the **Email Verification Protocol (EVP) specifications**.

> [!IMPORTANT]
> **Do I need to register an Origin Trial token to test EVP on `localhost`?**
> **No.** For `localhost` testing (`http://localhost:3000`), you **do NOT need to register an Origin Trial token** or own a public domain.
> Simply enable **`chrome://flags/#email-verification-protocol`** in Chrome (or launch Chrome from the terminal with `--enable-features=EmailVerificationProtocol`).
>
> **Why this also fixes Chrome 156 (`No verification token was sent by the browser`):**
> The Email Verification Protocol Origin Trial was configured for **Chrome 150–155**. On **Chrome 156+**, a website's `Origin-Trial` token alone no longer activates EVP unless `chrome://flags/#email-verification-protocol` (`--enable-features=EmailVerificationProtocol`) is enabled.

---

## Key Protocol Features Implemented

Both the Node.js verifier/issuer (`evp-core.js` + `server.js`) and the client-side verifier (`app.js` + `index.html`) implement the full EVP specification:

- **RFC 9421 HTTP Message Signatures (`Signature-Input` & `Signature-Key`)**:
  - Supports Chrome 154–156's default covered components `("@method" "@target-uri" "content-digest" "sec-fetch-dest" "signature-key")` as well as backward compatibility with Chrome 153's `("@method" "@authority" "@path" "content-digest" "signature-key")`.
  - Dynamically reconstructs `@signature-params` in the exact component order specified by the browser and parses both quoted and unquoted RFC 8941 `Signature-Key` (`hwk`) parameters.
- **`Sec-Fetch-Dest: email-verification`**:
  - Issuance endpoint accepts Chrome 154–156's hyphenated `Sec-Fetch-Dest: email-verification` header (plus Chrome 153's `emailverification`) and rejects invalid destinations.
- **Optional `kid` in EVT Header (Gmail Compatibility)**:
  - Gmail omits `kid` in its `evt+jwt` header. Both `evp-core.js` and `app.js` prioritize `kid`-matching JWKS keys when `kid` is present and automatically iterate through all candidate JWKS keys when `kid` is omitted.
- **Dual `EdDSA` (`Ed25519`) & `ES256` (`ECDSA P-256`) Support**:
  - Full cryptographic generation and verification support for both `EdDSA` (`OKP` / `Ed25519`) and `ES256` (`EC` / `P-256`) across Issuer EVTs (`evt+jwt`) and Browser Ephemeral Holder keys (`cnf.jwk`, `Signature-Key`, `kb+jwt`).
- **Exact `email` Claim Casing Preservation (Chrome 156+)**:
  - Preserves the exact email casing submitted by the user (e.g., `First.Last@evp.local`) in the issued `evt+jwt` and verified output.
- **`emailverified` Event Handling & Runtime `EmailVerifiedEvent` Detection**:
  - Listens for the `emailverified` DOM event (`e.presentationToken || e.detail?.presentationToken`) and checks `'EmailVerifiedEvent' in window` at runtime to warn Chrome 156+ users if `chrome://flags/#email-verification-protocol` is disabled.

---

## Quick Start: Run & Test on `localhost` (Zero Dependencies)

Requires **Node.js 20+ / 22+**. No `npm install` is needed because `server.js`, `evp-core.js`, and `test/evp.test.js` use only built-in Node.js modules (`node:http`, `node:crypto`, `node:dns/promises`, `node:test`).

### 1. Run the Automated Test Suite
```bash
npm test
# or directly:
node --test test/evp.test.js
```

### 2. Start the Localhost Verifier, Mock Issuer & Static Demo Server
```bash
npm start
# or directly:
node server.js
```

Then open your browser to:
- **`http://localhost:3000/`** — **Server-Side Localhost Verifier & RFC 9421 Mock Issuer** (with 1-click offline browser simulation, `EdDSA`/`ES256` & `kid` toggles, and native Chrome 150–156+ form submission).
- **`http://localhost:3000/index.html`** — **Client-Side SPA Verifier & Protocol Inspector** (with 1-click in-browser `EdDSA`/`ES256` simulator, `emailverified` listener, and Google DoH lookup).
- **`http://localhost:3000/traditional.html`** — **Traditional Auth (6-Digit OTP & Magic Link) Friction Benchmark**.
- **`http://localhost:3000/explainer.html`** — **Interactive EVP Architecture Explainer**.
- **`http://localhost:3000/glossary.html`** — **EVP & Cryptographic Glossary**.

---

## Interactive Demo Pages Overview

1. **🖥️ [Localhost Server & Mock Issuer](server.js)** (`http://localhost:3000/`):
   - Full server-side Relying Party Verifier + RFC 9421 Mock Issuer (`/.well-known/email-verification`, `/.well-known/vc-public-jwks`, `/email-verification/issuance`, `/api/simulate-browser-issuance`).
   - Allows toggling `EdDSA (Ed25519)` vs. `ES256 (ECDSA P-256)` and `kid` included vs. omitted (Gmail compatibility mode).

2. **⚡ [Client-Side EVP Protocol Page](index.html)** (`index.html` + `app.js`):
   - Demonstrates 1-click instant in-browser cryptographic verification via Chrome autofill (`emailverified` event) or the built-in **⚡ Simulate Browser EVP Flow & Verify** button.
   - Zero context switches, zero SMTP infrastructure, sub-second latency (~0.2s).

3. **✉️ [Traditional Auth Page](traditional.html)** (`traditional.html`):
   - Interactive simulation of legacy **6-Digit OTP** and **Magic Link** authentication.
   - Features a **Live Friction & Latency Stopwatch**, **App Context Switch Counter (2 switches)**, **Drop-off Probability Calculator**, and **Simulated Email Inbox Widget**.

---

## Troubleshooting Chrome 156: Why `No verification token was sent by the browser` Happens on `rowan.fyi` vs. `localhost`

If you test `https://rowan.fyi/made/email-verification` on **Chrome 156** and see:
> `Requires Chrome 150+, you're on Chrome 156: the API is supported.`
> `✅ Signed in to the demo provider as demo@rowan.fyi.`
> `⚠️ Verification failed. No verification token was sent by the browser.`

There are **3 root causes** (all resolved in this repository):

1. **Origin Trial Milestone Ceiling (`M150–155` vs. `Chrome 156`)**:
   - The Chrome Origin Trial token embedded in `rowan.fyi/made/email-verification` only covers **Chrome 150–155**. On **Chrome 156**, the Origin Trial token does not activate `EmailVerificationProtocol` unless **`chrome://flags/#email-verification-protocol`** (`--enable-features=EmailVerificationProtocol`) is enabled.
   - Meanwhile, `rowan.fyi` only checks `Chrome/156 >= 150` in `navigator.userAgent` rather than checking `'EmailVerifiedEvent' in window`. Both `server.js` and `app.js` in this repo check `'EmailVerifiedEvent' in window` at runtime and warn you if the flag is disabled.
2. **RFC 9421 `Signature-Input` Component Change (`@target-uri` vs. `@authority` / `@path`)**:
   - Chrome 154–156 sends `Signature-Input: sig=("@method" "@target-uri" "content-digest" "sec-fetch-dest" "signature-key");created=...`, whereas `rowan.fyi`'s `issuance.ts` hardcoded `["@method", "@authority", "@path", "content-digest", "signature-key"]` and rejected Chrome 154–156 requests with `400 Bad Request`.
   - `evp-core.js` supports both `"@target-uri"` (Chrome 154–156) and `"@authority"` + `"@path"` (Chrome 153).
3. **Exiting (`blur`) the Email Input Field Before Clicking Verify / Sign Up**:
   - When typing an email address instead of selecting an autofill suggestion, Chrome triggers the background EVP issuance flow when the user **exits (`blur` / presses `Tab`)** the `<input type="email">` field. Always press `Tab` and wait ~1 second for the inline checkmark (or `emailverified` event) before clicking Verify / Sign Up.

---

## Implementation Blueprints & Guides

1. **[Partner Localhost Testing Guide](PARTNER_LOCALHOST_GUIDE.md)**: Complete walkthrough for testing EVP on `localhost` without a public domain or Origin Trial token (Workflow A: Offline Mock Issuer, Workflow B: Native Chrome + `@gmail.com` on `http://localhost:3000`, Workflow C: Local Custom C++ Issuer with `dnsmasq` + `mkcert`).
2. **[Client-Side (SPA) Blueprint](EVP_IMPLEMENTATION_GUIDE.md)**: Serverless browser verification guide using `jose` and Google DNS-over-HTTPS (`https://dns.google/resolve`).
3. **[Server-Side (Node.js/Express) Blueprint](EVP_SERVER_IMPLEMENTATION_GUIDE.md)**: Production server-side verification architecture using Node.js `crypto` and `dns`.

---

## How to Test with Your Personal Gmail on `localhost` or GitHub Pages

### Step 1: Enable `chrome://flags/#email-verification-protocol`
Open Chrome (150–156+) and enable `chrome://flags/#email-verification-protocol`, or launch from the terminal:

* **macOS**:
  ```bash
  /Applications/Google\ Chrome\ Canary.app/Contents/MacOS/Google\ Chrome\ Canary --enable-features=EmailVerificationProtocol http://localhost:3000
  ```
* **Linux**:
  ```bash
  google-chrome-unstable --enable-features=EmailVerificationProtocol http://localhost:3000
  ```
* **Windows**:
  ```cmd
  start chrome-canary --enable-features=EmailVerificationProtocol http://localhost:3000
  ```

### Step 2: Ensure You Are Logged In
Make sure you are signed in to your `@gmail.com` account at `https://accounts.google.com` in that Chrome profile.

### Step 3: Trigger Verification
1. Open `http://localhost:3000` (or `http://localhost:3000/index.html` or your GitHub Pages URL).
2. Select your `@gmail.com` address from the autofill dropdown (or type it and press **Tab** to blur the field).
3. Approve the one-time Chrome prompt if shown, wait for the inline checkmark (`emailverified` event), and click **Verify / Sign up**!