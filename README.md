# Email Verification Protocol (EVP) - Relying Party (RP) Demo

This repository contains a simple, premium, and fully client-side implementation of a **Relying Party (RP)** website that verifies user email addresses using the new **Email Verification Protocol (EVP)**. 

Because this implementation is 100% client-side (serverless), it is fully compatible with and ready to be deployed directly to **GitHub Pages**.

---

## How It Works (Client-Side Cryptographic Verification)
Normally, cryptographic verification of the EVP token happens on the server side to prevent client-side bypasses. However, for the purpose of a public demo and hosting on static environments like GitHub Pages, this project implements the entire **6-step verification pipeline** directly in the browser:

1. **Token Decomposition & Parsing**: Splits the token at the `~` character into the Identity Provider's token (`SD-JWT`) and the browser's binding token (`KB-JWT`), and decodes their payloads.
2. **Local Claims & Session Binding**: Verifies matching email, verification status, audience, and matches the SHA-256 hash of the `SD-JWT` against the `sd_hash` in the `KB-JWT`.
3. **DNS Delegation Authority Verification**: Uses **DNS-over-HTTPS (DoH)** via `https://dns.google/resolve` to query DNS TXT records (`_email-verification.<email-domain>`) and check if the email domain delegates authority to the token issuer.
4. **Issuer Discovery & JWKS Fetching**: Discovers the issuer's endpoints and retrieves public keys (`JWKS`). A built-in dictionary handles CORS restrictions for known issuers (like Google and Rowan's demo).
5. **Issuer Signature Verification**: Cryptographically verifies the `SD-JWT` signature using the issuer's public keys via the `jose` library.
6. **Ephemeral Key Binding Verification**: Imports the ephemeral public key from the `SD-JWT` and verifies the signature of the browser's `KB-JWT` to prove possession of the private key.

---

## How to Test with Your Personal Gmail

To test this protocol with your personal Gmail address, you need to use Chrome Canary or Dev channel with the experimental flag enabled.

### Step 1: Launch Chrome Canary with the EVP Flag
Open your terminal and launch Chrome Canary with the `EmailVerificationProtocol` feature enabled:

* **macOS**:
  ```bash
  /Applications/Google\ Chrome\ Canary.app/Contents/MacOS/Google\ Chrome\ Canary --enable-features=EmailVerificationProtocol
  ```
* **Linux**:
  ```bash
  google-chrome-unstable --enable-features=EmailVerificationProtocol
  ```
* **Windows**:
  ```cmd
  start chrome-canary --enable-features=EmailVerificationProtocol
  ```

*Alternatively, navigate to `chrome://flags/#email-verification-protocol` in Chrome Canary, change the setting to **Enabled**, and restart the browser.*

### Step 2: Ensure You Are Logged In
Make sure you are logged into your `@gmail.com` account in the browser session.

### Step 3: Trigger Verification on the Demo Site
1. Open the demo site (either locally or on GitHub Pages).
2. Click into the **Email Address** input field.
3. Chrome will display an autofill dropdown showing your saved `@gmail.com` account.
4. Select your email. The first time, Chrome will show a one-time consent prompt: *"Allow Chrome to verify your email address on supported sites?"*
5. Click **Allow**. Chrome will automatically populate the hidden cryptographic token.
6. Click **Sign Up**. The site will run the 6-step verification trace and display a success banner!

---

## Local Development & Testing

Since ES modules are loaded dynamically, opening the `index.html` file directly via the `file://` protocol will trigger browser CORS security blocks. You must run a local web server:

1. Start the local server:
   ```bash
   npm run start
   ```
2. Open your browser and navigate to:
   ```
   http://localhost:3000
   ```

*Note: If you do not have Node/NPM installed, you can run any static server in this directory, for example:*
* **Python 3**: `python3 -m http.server 3000`
* **Ruby**: `ruby -run -ehttpd . -p3000`

---

## GitHub Pages Deployment

To host this on GitHub Pages:

1. Create a new repository on GitHub.
2. Commit and push the files in this directory (`index.html`, `style.css`, `app.js`) to the root of your repository's `main` or `master` branch.
3. Go to your repository's **Settings** > **Pages**.
4. Under **Build and deployment**, select **Deploy from a branch**, choose your branch (e.g., `main`), and set the folder to `/ (root)`.
5. Click **Save**. Your site will be live at `https://<username>.github.io/<repository-name>/` within a few minutes.