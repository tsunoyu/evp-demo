# Partner Guide: Testing the Email Verification Protocol (EVP) on `localhost`

> **Short Answer for Partners:**
> 1. **You can test the Email Verification Protocol (EVP) end-to-end on `http://localhost:3000` without owning, configuring, or deploying to a public domain.**
> 2. **You do NOT need to register an Origin Trial token for `localhost` testing.** Simply enable **`chrome://flags/#email-verification-protocol`** in Chrome (or launch Chrome with `--enable-features=EmailVerificationProtocol`). This also enables EVP on **Chrome 156+**, where the M150–155 Origin Trial token no longer applies.

---

## 1. Choose Your Testing Path by Role

| Partner Role | Goal | Needs Public Domain? | Needs Origin Trial Registration? | Needs Local HTTPS (`mkcert`)? | Recommended Workflow |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **Relying Party (Website / App)** | Test Chrome 150–156+ native autofill (`autocomplete="email-verification-token"`) & backend verification on `http://localhost:3000` | **No** | **No** (use `chrome://flags/#email-verification-protocol`) | **No** (`http://localhost` is a Secure Context) | **Workflow 1**: Enable `chrome://flags/#email-verification-protocol` and test `http://localhost:3000` with a signed-in `@gmail.com` account |
| **Relying Party Backend / QA** | Automated CI/CD & offline testing of the 6-step SD-JWT+KB verification logic (`EdDSA` / `ES256`, omitted `kid`, nonce replay, Chrome 154–156 `Signature-Input`) | **No** | **No** | **No** | **Workflow 2**: Use the local Mock Issuer & RFC 9421 Browser Simulator (`node --test test/evp.test.js` & `node server.js`) |
| **Email Provider (Issuer)** | Test Chrome's native C++ discovery (`/.well-known/email-verification`) & RFC 9421 issuance against a local Issuer | **No** | **No** (use `chrome://flags/#email-verification-protocol`) | **Yes** (for the Issuer origin only) | **Workflow 3**: Map a PSL TLD (`issuer.evp-local.dev`) to `127.0.0.1` via `dnsmasq` + `mkcert` |

---

## 2. Workflow 1: Relying Party (Website) Testing on `http://localhost:3000` with Live Chrome 150–156+

If you are a website or app developer (Relying Party), you can test **Chrome's real native EVP implementation** against your local development server (`http://localhost:3000`) without registering an Origin Trial.

### Step 1: Enable the Chrome Flag (Recommended — No Origin Trial Registration Needed)

- **Recommended (`chrome://flags` or CLI flag — Required on Chrome 156+):**
  Enable **`chrome://flags/#email-verification-protocol`** in Chrome and relaunch, **or** launch Chrome from the terminal:
  ```bash
  # macOS (Chrome Canary / Dev / Stable)
  /Applications/Google\ Chrome\ Canary.app/Contents/MacOS/Google\ Chrome\ Canary --enable-features=EmailVerificationProtocol http://localhost:3000

  # Linux
  google-chrome-unstable --enable-features=EmailVerificationProtocol http://localhost:3000
  ```
  *Why this is recommended:* You do **not** need to register `http://localhost:3000` on the Chrome Origin Trials console, and it works on **Chrome 156+** (whereas the M150–155 Origin Trial token does not apply on Chrome 156).

### Step 2: Add the EVP Markup & Event Listener to Your `localhost` Form

Generate a single-use cryptographic `nonce` on your server (stored in an `HttpOnly` session cookie) and render:

```html
<form action="/verify-email" method="POST" id="signup-form">
  <label for="email">Email address</label>
  <input type="email" id="email" name="email" autocomplete="email" required />

  <!-- Chrome populates this hidden input with `<EVT>~<KB-JWT>` -->
  <input
    type="hidden"
    id="evp-token"
    name="token"
    nonce="<SERVER_GENERATED_SINGLE_USE_UUID>"
    autocomplete="email-verification-token"
  />

  <button type="submit">Continue</button>
</form>

<script>
  // Listen for the 'emailverified' event (Chrome 152+)
  const emailInput = document.getElementById('email');
  const tokenInput = document.getElementById('evp-token');
  emailInput.addEventListener('emailverified', (e) => {
    const token = e.presentationToken || e.detail?.presentationToken;
    if (token) {
      tokenInput.value = token;
      console.log('Received EVP presentationToken:', token);
    }
  });
</script>
```

### Step 3: Sign In to a Participating Provider, Blur the Email Input, and Submit

1. In the same Chrome profile, sign in to any personal **`@gmail.com`** account at `https://accounts.google.com`.
2. Visit `http://localhost:3000`, enter your `@gmail.com` address, and **press `Tab` or click outside the email field (`blur`)**.
   - **Important:** Wait ~1 second for Chrome's inline verification spinner at the right edge of the email input to turn into a **checkmark** before clicking **Continue / Sign up**.
3. Chrome signs the Key Binding JWT (`kb+jwt`) with `"aud": "http://localhost:3000"` and `"nonce": "<SERVER_GENERATED_SINGLE_USE_UUID>"`.
4. Your `localhost:3000` backend verifies the token against the live DNS TXT record (`_email-verification.gmail.com`) and live HTTPS JWKS endpoint (`https://verifiablecredentials-pa.googleapis.com/.well-known/vc-public-jwks`).

---

## 3. Troubleshooting Chrome 156: Why `No verification token was sent by the browser` Happens on `rowan.fyi`

When testing `https://rowan.fyi/made/email-verification` on **Chrome 156**, partners have reported seeing:
> `Requires Chrome 150+, you're on Chrome 156: the API is supported.`
> `✅ Signed in to the demo provider as demo@rowan.fyi.`
> `⚠️ Verification failed. No verification token was sent by the browser.`

Here is why that happens and what needs to be updated in `rowan-fyi` vs. how our `evp-localhost-demo` handles it:

| Issue | What Happens on `rowan.fyi` (`index.astro` / `issuance.ts`) | Fix for Partners & What `evp-localhost-demo` Does |
| :--- | :--- | :--- |
| **1. Chrome 156 Origin Trial Expiry vs. UA Banner (`index.astro`)** | `rowan.fyi`'s `Origin-Trial` token covers **Chrome 150–155**. On **Chrome 156**, the trial token is inactive unless `chrome://flags/#email-verification-protocol` is enabled. However, `index.astro` only checks `Chrome/(\d+) >= 150` in `navigator.userAgent`, falsely displaying `"you're on Chrome 156: the API is supported"` even when `window.EmailVerifiedEvent` is `undefined`. | Enable **`chrome://flags/#email-verification-protocol`** (or `--enable-features=EmailVerificationProtocol`). In `server.js` (and recommended for `index.astro`), check `'EmailVerifiedEvent' in window` at runtime. |
| **2. RFC 9421 `Signature-Input` Component Mismatch (`issuance.ts`)** | `rowan-fyi/src/pages/made/email-provider/issuance.ts` lines 113–118 hardcode `const requiredComponents = ["@method", "@authority", "@path", "content-digest", "signature-key"]` and reject requests missing `"@authority"` or `"@path"`. However, **Chrome 154–156** sends `Signature-Input: sig=("@method" "@target-uri" "content-digest" "sec-fetch-dest" "signature-key");created=...` (using `@target-uri` instead of `@authority` + `@path`), causing `issuance.ts` to fail with `400 Bad Request`. | Update `issuance.ts` so the target requirement accepts `"@target-uri"` **or** `"@authority"` + `"@path"`, and include `"sec-fetch-dest"` when covered. `evp-core.js` defaults to `("@method" "@target-uri" "content-digest" "sec-fetch-dest" "signature-key")` and dynamically verifies both! |
| **3. Clicking "Sign up" Before Blurring the Email Field** | If a user types an email address and immediately clicks **Sign up** without first exiting (`blur`) the email input and waiting for the inline verification checkmark, Chrome has not yet completed the background `/issuance` request. | Press **Tab** or click outside the email field after typing, wait for the inline verification checkmark (or listen for the `emailverified` event), and then submit. |

---

## 4. Workflow 2: 100% Offline Localhost Testing (Backend Verifier + Mock Issuer Simulator)

To test your backend verification code in automated unit/integration tests (`node --test`) or without external network access, use the included **Localhost Reference Demo** (`server.js` + `evp-core.js`):

```bash
# 1. Run the 17-test automated verification suite (zero npm dependencies, Node 20+/22+)
node --test test/evp.test.js

# 2. Start the local Verifier + Mock Issuer server on http://localhost:3000
node server.js
```

---

## 5. Workflow 3: Testing a Custom Email Provider (Issuer) Against Chrome's Native C++ Stack

If you are an **Email Provider (Issuer)** testing your own `.well-known/email-verification` and `/issuance` endpoints against Chrome's native C++ `EmailVerifierImpl` (`content/browser/email_verification/email_verifier_impl.cc`) locally, be aware of two strict checks in Chromium's C++ implementation:

1. **Use a Real Public Suffix List (PSL) TLD (`.dev`, `.org`, `.com`) — Do NOT use `.test`, `.localhost`, or `.example`:**
   Chromium's `GetEmailDomainFromEmail()` calls `net::registry_controlled_domains::GetDomainAndRegistry(..., INCLUDE_PRIVATE_REGISTRIES)`. Reserved non-PSL TLDs (`.test`, `.example`, `.localhost`) return `""` and abort verification before any DNS query is made. Always use a synthetic domain under a valid PSL TLD (e.g., `user@issuer.evp-local.dev`).
2. **Serve the Local Issuer over `https://` (`mkcert`):**
   While the Relying Party works over plain `http://localhost:3000`, Chromium's `ConstructEmailVerificationUrl()` hardcodes `url::kHttpsScheme` (`https://<issuer>/.well-known/email-verification`).

### Local Custom Issuer Setup (`dnsmasq` + `mkcert`):
1. **Configure `dnsmasq` for `issuer.evp-local.dev`**:
   ```ini
   address=/issuer.evp-local.dev/127.0.0.1
   txt-record=_email-verification.issuer.evp-local.dev,"iss=issuer.evp-local.dev"
   ```
2. **Generate a locally trusted TLS certificate with `mkcert`**:
   ```bash
   mkcert -install
   mkcert issuer.evp-local.dev localhost 127.0.0.1
   ```
3. **Launch Chrome with Host Resolver Rules**:
   ```bash
   google-chrome-unstable \
     --enable-features=EmailVerificationProtocol \
     --host-resolver-rules="MAP issuer.evp-local.dev 127.0.0.1" \
     http://localhost:3000
   ```
