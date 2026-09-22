'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {
  createMockIssuerKeys,
  generateEd25519KeyPairJwk,
  verifyEvpToken,
  handleIssuanceRequest,
  simulateBrowserEvpFlow,
} = require('./evp-core');

const NONCE_COOKIE_NAME = 'evp_rp_nonce';
const SESSION_COOKIE_NAME = '__session';
const DEFAULT_LOCAL_EMAIL = 'demo@localhost.example';

function parseCookies(cookieHeader = '') {
  const cookies = {};
  for (const pair of cookieHeader.split(';')) {
    const idx = pair.indexOf('=');
    if (idx > 0) {
      const k = pair.slice(0, idx).trim();
      const v = pair.slice(idx + 1).trim();
      cookies[k] = decodeURIComponent(v);
    }
  }
  return cookies;
}

function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function renderVerifierPage({
  origin,
  activeNonce,
  providerSignedIn,
  includeKidInEvt,
  activeIssuerAlg,
  submittedEmail,
  verificationResult,
  errorMsg,
  activeTrace,
}) {
  const traceHtml = activeTrace
    ? `
      <div class="trace-container">
        <h2>6-Step Verification Trace</h2>
        <p class="subtitle">Expand each step below to inspect the exact inputs sent, servers queried, and cryptographic outputs received:</p>
        <ol class="trace-list">
          ${activeTrace
            .map(
              (step) => `
            <li class="trace-step ${escapeHtml(step.status)}">
              <div class="trace-step-header">
                <h3 class="trace-step-title">${escapeHtml(step.name)}</h3>
                <span class="status-badge">${escapeHtml(step.status === 'pending' ? 'not run' : step.status)}</span>
              </div>
              <p class="trace-step-desc">${escapeHtml(step.description)}</p>
              ${step.error ? `<p class="trace-step-error"><strong>Error:</strong> ${escapeHtml(step.error)}</p>` : ''}
              ${
                step.serverCalled || step.inputSent || step.outputReceived
                  ? `
                <details class="trace-details" ${step.status === 'failed' ? 'open' : ''}>
                  <summary>Show debugging detail</summary>
                  <div class="trace-details-content">
                    ${
                      step.serverCalled
                        ? `<p><strong>Server / Resolver Called:</strong> <code>${escapeHtml(step.serverCalled)}</code></p>`
                        : ''
                    }
                    ${
                      step.inputSent
                        ? `<div class="trace-section-mb">
                            <strong>Inputs Sent:</strong>
                            <code class="trace-json">${escapeHtml(JSON.stringify(step.inputSent, null, 2))}</code>
                          </div>`
                        : ''
                    }
                    ${
                      step.outputReceived
                        ? `<div class="trace-section-mb">
                            <strong>Outputs Received:</strong>
                            <code class="trace-json">${escapeHtml(JSON.stringify(step.outputReceived, null, 2))}</code>
                          </div>`
                        : ''
                    }
                  </div>
                </details>
              `
                  : ''
              }
            </li>
          `
            )
            .join('')}
        </ol>
      </div>
    `
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Localhost EVP Verifier & Mock Issuer Demo</title>
  <style>
    :root {
      color-scheme: light;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    body {
      max-width: 920px;
      margin: 0 auto;
      padding: 2rem 1.25rem 4rem;
      color: #1f2937;
      background: #f9fafb;
      line-height: 1.55;
    }
    h1 { margin-bottom: 0.25rem; font-size: 1.75rem; }
    .subtitle { color: #4b5563; margin-top: 0; font-size: 0.95rem; }
    .card {
      background: #fff;
      border: 1px solid #e5e7eb;
      border-radius: 8px;
      padding: 1.25rem 1.5rem;
      margin-bottom: 1.25rem;
      box-shadow: 0 1px 2px rgba(0,0,0,0.03);
    }
    .grid-2 {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 1rem;
    }
    .badge {
      display: inline-block;
      padding: 0.15rem 0.55rem;
      border-radius: 999px;
      font-size: 0.8rem;
      font-weight: 600;
    }
    .badge.green { background: #d1fae5; color: #065f46; }
    .badge.amber { background: #fef3c7; color: #92400e; }
    .form-group { margin-bottom: 1rem; }
    label { display: block; font-weight: 600; margin-bottom: 0.35rem; font-size: 0.92rem; }
    input[type="email"] {
      width: 100%;
      box-sizing: border-box;
      padding: 0.65rem 0.75rem;
      font-size: 1rem;
      border: 1px solid #d1d5db;
      border-radius: 6px;
    }
    .btn-row { display: flex; flex-wrap: wrap; gap: 0.55rem; align-items: center; }
    button {
      padding: 0.55rem 0.95rem;
      font-size: 0.88rem;
      font-weight: 600;
      border-radius: 6px;
      cursor: pointer;
      border: 1px solid transparent;
    }
    .btn-primary { background: #1d4ed8; color: #fff; }
    .btn-primary:hover { background: #1e40af; }
    .btn-secondary { background: #eff6ff; color: #1e40af; border-color: #bfdbfe; }
    .btn-secondary:hover { background: #dbeafe; }
    .btn-outline { background: #fff; color: #374151; border-color: #d1d5db; }
    .btn-outline:hover { background: #f3f4f6; }
    .msg-box {
      padding: 1rem 1.25rem;
      border-radius: 8px;
      margin-bottom: 1.25rem;
    }
    .msg-box.success { background: #ecfdf5; border: 1px solid #6ee7b7; color: #065f46; }
    .msg-box.error { background: #fef2f2; border: 1px solid #fca5a5; color: #991b1b; }
    .msg-box h3 { margin: 0 0 0.35rem 0; }
    .trace-container { margin-top: 1.5rem; }
    .trace-list { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 0.75rem; }
    .trace-step {
      background: #fff;
      border: 1px solid #e5e7eb;
      border-left: 5px solid #9ca3af;
      border-radius: 6px;
      padding: 0.9rem 1.1rem;
    }
    .trace-step.success { border-left-color: #10b981; background: #f0fdf4; }
    .trace-step.failed { border-left-color: #ef4444; background: #fef2f2; }
    .trace-step-header { display: flex; justify-content: space-between; align-items: center; }
    .trace-step-title { margin: 0; font-size: 1rem; }
    .status-badge {
      font-size: 0.75rem;
      text-transform: uppercase;
      font-weight: 700;
      padding: 0.15rem 0.5rem;
      border-radius: 4px;
      background: #e5e7eb;
    }
    .trace-step.success .status-badge { background: #a7f3d0; color: #065f46; }
    .trace-step.failed .status-badge { background: #fecaca; color: #991b1b; }
    .trace-step-desc { margin: 0.35rem 0 0; font-size: 0.88rem; color: #4b5563; }
    .trace-step-error { margin: 0.5rem 0 0; font-size: 0.88rem; color: #b91c1c; }
    .trace-details { margin-top: 0.65rem; }
    .trace-details summary { font-size: 0.85rem; font-weight: 600; color: #1d4ed8; cursor: pointer; }
    .trace-details-content {
      margin-top: 0.5rem;
      padding: 0.75rem;
      background: #fff;
      border: 1px solid #d1d5db;
      border-radius: 4px;
    }
    .trace-section-mb { margin-bottom: 0.75rem; }
    .trace-section-mb:last-child { margin-bottom: 0; }
    .trace-json {
      display: block;
      margin-top: 0.25rem;
      padding: 0.5rem;
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 4px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 0.82rem;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }
    code {
      background: #f1f5f9;
      padding: 0.1rem 0.35rem;
      border-radius: 4px;
      font-size: 0.88em;
    }
  </style>
</head>
<body>
  <nav style="display:flex; flex-wrap:wrap; gap:0.5rem; align-items:center; justify-content:space-between; padding:0.75rem 1rem; margin-bottom:1.25rem; background:#fff; border:1px solid #e5e7eb; border-radius:8px; box-shadow:0 1px 2px rgba(0,0,0,0.03);">
    <div style="font-weight:700; font-size:0.95rem; display:flex; align-items:center; gap:0.4rem;">
      <span>🔒</span> <span>EVP Verifier &amp; Localhost Demo Suite</span>
    </div>
    <div style="display:flex; flex-wrap:wrap; gap:0.5rem; font-size:0.86rem;">
      <a href="/" style="padding:0.35rem 0.65rem; border-radius:6px; background:#eff6ff; color:#1d4ed8; font-weight:600; text-decoration:none;">🖥️ Localhost Server &amp; Mock Issuer</a>
      <a href="/index.html" style="padding:0.35rem 0.65rem; border-radius:6px; color:#374151; font-weight:500; text-decoration:none;">⚡ Client-Side SPA Verifier</a>
      <a href="/traditional.html" style="padding:0.35rem 0.65rem; border-radius:6px; color:#374151; font-weight:500; text-decoration:none;">✉️ Traditional Auth</a>
      <a href="/explainer.html" style="padding:0.35rem 0.65rem; border-radius:6px; color:#374151; font-weight:500; text-decoration:none;">🧭 EVP Explainer</a>
      <a href="/glossary.html" style="padding:0.35rem 0.65rem; border-radius:6px; color:#374151; font-weight:500; text-decoration:none;">📖 Glossary</a>
    </div>
  </nav>
  <h1>Relying Party — Localhost Email Verification Protocol (EVP) Demo</h1>
  <p class="subtitle">
    Test the <a href="https://github.com/WICG/email-verification" target="_blank">Email Verification API</a> &amp;
    <a href="https://www.ietf.org/archive/id/draft-hardt-email-verification-00.html" target="_blank">SD-JWT+KB Protocol</a>
    entirely on <code>${escapeHtml(origin)}</code> without needing a public domain.
  </p>

  <div class="grid-2">
    <div class="card">
      <h3 style="margin-top:0">Mode A: Localhost Mock Provider (100% Offline)</h3>
      <p style="font-size:0.9rem; margin-bottom:0.75rem">
        Session status for <code>${escapeHtml(DEFAULT_LOCAL_EMAIL)}</code>:
        ${
          providerSignedIn
            ? '<span class="badge green">Signed In (__session=active)</span>'
            : '<span class="badge amber">Signed Out</span>'
        }
      </p>
      <div class="btn-row">
        <form method="POST" action="/email-provider/session" style="display:inline-block">
          <input type="hidden" name="action" value="${providerSignedIn ? 'logout' : 'login'}" />
          <button type="submit" class="btn-outline">
            ${providerSignedIn ? 'Sign Out of Local Provider' : 'Sign In as demo@localhost.example'}
          </button>
        </form>
        <form method="POST" action="/email-provider/toggle-kid" style="display:inline-block">
          <button type="submit" class="btn-outline" title="Gmail omits kid in EVT header; toggle to test both paths">
            EVT Header kid: <strong>${includeKidInEvt ? 'Included' : 'Omitted (Gmail style)'}</strong>
          </button>
        </form>
        <form method="POST" action="/mock-provider/toggle-alg" style="display:inline-block">
          <button type="submit" class="btn-outline" title="Switch Mock Issuer &amp; Ephemeral Holder between EdDSA (Ed25519) and ES256 (ECDSA P-256)">
            Issuer Key Alg: <strong>${activeIssuerAlg === 'ES256' ? 'ES256 (ECDSA P-256)' : 'EdDSA (Ed25519)'}</strong>
          </button>
        </form>
      </div>
      <p style="font-size:0.82rem; color:#6b7280; margin-bottom:0; margin-top:0.65rem">
        Local DNS override: <code>_email-verification.localhost.example</code> &rarr; <code>iss=${escapeHtml(origin)}</code>
      </p>
    </div>

    <div class="card">
      <h3 style="margin-top:0">Mode B: Native Chrome 150–156+ &amp; Real Provider (No Origin Trial Token Needed!)</h3>
      <p style="font-size:0.88rem; margin-bottom:0.5rem">
        Browser: <strong id="ua-status">Checking...</strong>
      </p>
      <ol style="font-size:0.84rem; padding-left:1.2rem; margin:0; color:#374151">
        <li><strong>Enable Chrome Flag (No Origin Trial Registration Needed):</strong> Enable <code>chrome://flags/#email-verification-protocol</code> or launch with <code>--enable-features=EmailVerificationProtocol</code>. <em>(Required on Chrome 156+, where M150–155 Origin Trial tokens do not apply!)</em></li>
        <li>Sign in to your <code>@gmail.com</code> account (or <a href="https://rowan.fyi/made/email-provider" target="_blank">rowan.fyi/made/email-provider</a> for <code>demo@rowan.fyi</code>).</li>
        <li>Enter that email below, <strong>Tab / click out of the email field (<code>blur</code>)</strong> and wait for the inline checkmark, then press <strong>Sign up (Native Form Submit)</strong>.</li>
      </ol>
      <p style="font-size:0.8rem; color:#6b7280; margin-bottom:0; margin-top:0.55rem">
        <strong>Mode C (Custom Local C++ Issuer):</strong> In Chromium's <code>content/browser/email_verification/email_verifier_impl.cc</code>, <code>ConstructEmailVerificationUrl</code> enforces <code>url::kHttpsScheme</code> and <code>GetEmailDomainFromEmail</code> checks <code>net::registry_controlled_domains::GetDomainAndRegistry</code> (PSL), so use <code>issuer.evp-local.dev</code> (not <code>.test</code>/<code>.example</code>) with <code>dnsmasq</code> + <code>mkcert</code>.
      </p>
    </div>
  </div>

  <div class="card">
    <h2 style="margin-top:0; font-size:1.25rem">Sign-Up / Verification Form</h2>
    <p style="font-size:0.88rem; color:#4b5563; margin-top:0">
      Active single-use session nonce (<code>${escapeHtml(NONCE_COOKIE_NAME)}</code>): <code>${escapeHtml(activeNonce)}</code>
    </p>
    <form method="POST" action="/" id="verify-form">
      <div class="form-group">
        <label for="email">Email address:</label>
        <input
          type="email"
          id="email"
          name="email"
          autocomplete="email"
          placeholder="demo@localhost.example, yourname@gmail.com, or demo@rowan.fyi"
          value="${escapeHtml(submittedEmail || DEFAULT_LOCAL_EMAIL)}"
          required
        />
      </div>
      <!-- EVP Hidden Input with Server-Side Dynamic Nonce -->
      <input
        type="hidden"
        id="evp-token-input"
        name="token"
        nonce="${escapeHtml(activeNonce)}"
        autocomplete="email-verification-token"
      />
      <div class="btn-row">
        <button type="submit" id="submit-btn" class="btn-primary">
          Sign up (Native Form Submit)
        </button>
        <button type="button" id="simulate-btn" class="btn-secondary">
          ⚡ Simulate Browser EVP Flow (RFC 9421 Issuance + KB-JWT) &amp; Verify
        </button>
        <a href="/" style="font-size:0.88rem; color:#2563eb; margin-left:auto">Reload Fresh Nonce</a>
      </div>
    </form>
  </div>

  ${
    verificationResult
      ? `
    <div class="msg-box success">
      <h3>🎉 Email successfully verified via EVP!</h3>
      <p style="margin:0.25rem 0">
        Verified Email: <strong>${escapeHtml(verificationResult.email)}</strong>
        &nbsp;|&nbsp; Authoritative Issuer: <code>${escapeHtml(verificationResult.issuer)}</code>
      </p>
    </div>
  `
      : ''
  }

  ${
    errorMsg
      ? `
    <div class="msg-box error">
      <h3>⚠️ Verification failed</h3>
      <p style="margin:0.25rem 0">${escapeHtml(errorMsg)}</p>
      <p style="margin:0.35rem 0 0; font-size:0.88rem">
        Session nonces are single-use to prevent replay attacks. <a href="/">Reload the page</a> to generate a fresh nonce.
      </p>
    </div>
  `
      : ''
  }

  <div class="card" style="background:#fffbeb; border-color:#fcd34d">
    <h3 style="margin-top:0; font-size:1.05rem; color:#92400e">
      🔍 Why Chrome 156 Can Show &ldquo;No verification token was sent by the browser&rdquo; (<code>rowan.fyi</code> vs. <code>localhost</code>)
    </h3>
    <ol style="font-size:0.86rem; padding-left:1.25rem; margin:0; color:#4b5563">
      <li>
        <strong>Origin Trial Milestone Ceiling (M150&ndash;155 vs. Chrome 156):</strong>
        The Chrome Origin Trial token on <code>rowan.fyi</code> only covers Chrome 150&ndash;155, while <code>rowan.fyi</code>'s banner only checks <code>Chrome/(\d+) &gt;= 150</code> in the User-Agent string. On <strong>Chrome 156+</strong> (and on <code>http://localhost:3000</code>), you <strong>do NOT need an Origin Trial token</strong> &mdash; simply enable <code>chrome://flags/#email-verification-protocol</code> (or launch Chrome with <code>--enable-features=EmailVerificationProtocol</code>).
      </li>
      <li>
        <strong>RFC 9421 <code>Signature-Input</code> Component List (Chrome 154&ndash;156):</strong>
        <code>rowan.fyi/made/email-provider/issuance.ts</code> requires <code>["@method", "@authority", "@path", "content-digest", "signature-key"]</code> and rejects <code>@target-uri</code>, whereas Chrome 154&ndash;156 sends <code>("@method" "@target-uri" "content-digest" "sec-fetch-dest" "signature-key")</code>. This local server dynamically supports both!
      </li>
      <li>
        <strong>Blur the Email Field Before Clicking Sign Up:</strong>
        When typing an email manually, press <strong>Tab</strong> or click outside the email field (<code>blur</code>) and wait for Chrome's inline verification spinner &rarr; checkmark before clicking <strong>Sign up</strong>.
      </li>
    </ol>
  </div>

  ${traceHtml}

  <script>
    // Browser support & runtime flag detector
    (function () {
      const ua = navigator.userAgent;
      const isChrome = /Chrome\\/(\\d+)/i.test(ua) && !/Edg|OPR/i.test(ua);
      const match = isChrome ? ua.match(/Chrome\\/(\\d+)/i) : null;
      const version = match ? parseInt(match[1], 10) : 0;
      const hasEvpApi = typeof window !== 'undefined' && ('EmailVerifiedEvent' in window || 'onemailverified' in HTMLElement.prototype);
      const statusEl = document.getElementById('ua-status');
      if (statusEl) {
        if (isChrome && version >= 150 && hasEvpApi) {
          statusEl.textContent = 'Chrome ' + version + ' (Native EVP Active — No Origin Trial Needed on localhost)';
          statusEl.style.color = '#065f46';
        } else if (isChrome && version >= 156 && !hasEvpApi) {
          statusEl.textContent =
            'Chrome ' +
            version +
            ' detected, but EVP flag is OFF (M150–155 Origin Trial does not apply on M156; enable chrome://flags/#email-verification-protocol)';
          statusEl.style.color = '#b91c1c';
        } else if (isChrome && version >= 150) {
          statusEl.textContent =
            'Chrome ' + version + ' (Enable chrome://flags/#email-verification-protocol — No Origin Trial needed on localhost)';
          statusEl.style.color = '#065f46';
        } else {
          statusEl.textContent = (isChrome ? 'Chrome ' + version : 'Non-Chrome Browser') + ' (Use Local Simulator or Chrome 150+)';
          statusEl.style.color = '#92400e';
        }
      }
    })();

    const simulateBtn = document.getElementById('simulate-btn');
    const emailInput = document.getElementById('email');
    const tokenInput = document.getElementById('evp-token-input');
    const verifyForm = document.getElementById('verify-form');

    // Listen for the declarative/programmatic emailverified event (WICG Email Verification API)
    function onEmailVerified(e) {
      const token = e.presentationToken || (e.detail && e.detail.presentationToken);
      if (token && tokenInput) {
        tokenInput.value = token;
      }
    }
    if (emailInput) emailInput.addEventListener('emailverified', onEmailVerified);
    if (verifyForm) verifyForm.addEventListener('emailverified', onEmailVerified);

    // Localhost Browser EVP Simulator button handler
    if (simulateBtn && emailInput && tokenInput && verifyForm) {
      simulateBtn.addEventListener('click', async () => {
        simulateBtn.disabled = true;
        simulateBtn.textContent = 'Issuing EVT & signing KB-JWT...';
        try {
          const email = emailInput.value.trim() || '${escapeHtml(DEFAULT_LOCAL_EMAIL)}';
          const nonce = tokenInput.getAttribute('nonce');
          const res = await fetch('/api/simulate-browser-issuance', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, nonce }),
          });
          const data = await res.json();
          const token = data.presentation_token || data.presentationToken;
          if (!res.ok || !token) {
            alert('Local Issuance Error: ' + (data.error_description || data.error || 'Failed to issue token'));
            simulateBtn.disabled = false;
            simulateBtn.textContent = '⚡ Simulate Browser EVP Flow (RFC 9421 Issuance + KB-JWT) & Verify';
            return;
          }
          const ev = new CustomEvent('emailverified', {
            bubbles: true,
            detail: { presentationToken: token },
          });
          ev.presentationToken = token;
          emailInput.dispatchEvent(ev);
          tokenInput.value = token;
          verifyForm.submit();
        } catch (err) {
          alert('Simulation failed: ' + err.message);
          simulateBtn.disabled = false;
        }
      });
    }
  </script>
</body>
</html>`;
}

/**
 * Creates a standalone EVP Localhost HTTP Server (hosting both the Relying Party Verifier and Mock Issuer).
 */
function createEvpLocalhostServer(options = {}) {
  const ed25519KeyPair = options.issuerKeyPair || createMockIssuerKeys('EdDSA', 'localhost-issuer-key-ed25519', true);
  const p256KeyPair = createMockIssuerKeys('ES256', 'localhost-issuer-key-es256', true);
  // Secondary key in JWKS to demonstrate multi-key JWKS discovery (e.g. when kid is omitted)
  const secondaryKeyPair = generateEd25519KeyPairJwk('localhost-issuer-key-backup', true);

  let activeIssuerAlg = options.issuerAlg === 'ES256' ? 'ES256' : (ed25519KeyPair.alg || 'EdDSA');
  let includeKidInEvt = options.includeKidInEvt !== undefined ? Boolean(options.includeKidInEvt) : true;
  const originTrialToken = options.originTrialToken || process.env.ORIGIN_TRIAL_TOKEN || '';

  const getActiveIssuerKeyPair = () => (activeIssuerAlg === 'ES256' ? p256KeyPair : ed25519KeyPair);

  const server = http.createServer(async (req, res) => {
    const host = req.headers['x-evp-original-host'] || req.headers.host || 'localhost:3000';
    const protocol = req.headers['x-forwarded-proto'] || 'http';
    const origin = `${protocol}://${host}`;
    const parsedUrl = new URL(req.url || '/', origin);
    const pathname = parsedUrl.pathname;
    const cookies = parseCookies(req.headers.cookie);
    const providerSignedIn = cookies[SESSION_COOKIE_NAME] !== 'logged-out'; // Default signed-in for frictionless localhost testing

    if (originTrialToken) {
      res.setHeader('Origin-Trial', originTrialToken);
    }

    // -------------------------------------------------------------------------
    // 1. Issuer Discovery: /.well-known/email-verification
    // -------------------------------------------------------------------------
    if (req.method === 'GET' && pathname === '/.well-known/email-verification') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(
        JSON.stringify(
          {
            issuer: origin,
            issuance_endpoint: `${origin}/email-verification/issuance`,
            jwks_uri: `${origin}/.well-known/vc-public-jwks`,
            signing_alg_values_supported: ['EdDSA', 'ES256'],
          },
          null,
          2
        )
      );
    }

    // -------------------------------------------------------------------------
    // 2. FedCM / Web Identity Discovery: /.well-known/web-identity
    // -------------------------------------------------------------------------
    if (req.method === 'GET' && pathname === '/.well-known/web-identity') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(
        JSON.stringify(
          {
            accounts_endpoint: `${origin}/email-verification/accounts`,
            login_url: `${origin}/`,
          },
          null,
          2
        )
      );
    }

    // -------------------------------------------------------------------------
    // 3. Issuer Public JWKS: /.well-known/vc-public-jwks
    // -------------------------------------------------------------------------
    if (req.method === 'GET' && pathname === '/.well-known/vc-public-jwks') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(
        JSON.stringify(
          {
            // Place secondaryKeyPair first so that when `kid` is omitted (Gmail mode),
            // the Verifier must iterate past key[0] and succeed on the active signing key!
            keys: [secondaryKeyPair.publicJwk, ed25519KeyPair.publicJwk, p256KeyPair.publicJwk],
          },
          null,
          2
        )
      );
    }

    // -------------------------------------------------------------------------
    // 4. Accounts Endpoint: /email-verification/accounts
    // -------------------------------------------------------------------------
    if (req.method === 'GET' && pathname === '/email-verification/accounts') {
      if (!providerSignedIn) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'unauthenticated' }));
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(
        JSON.stringify({
          accounts: [
            {
              id: 'localhost-demo-user',
              name: 'Localhost Demo User',
              email: DEFAULT_LOCAL_EMAIL,
              given_name: 'Demo',
            },
          ],
        })
      );
    }

    // -------------------------------------------------------------------------
    // 5. Provider Login/Logout Toggle (Login Status API `Set-Login` header)
    // -------------------------------------------------------------------------
    if (req.method === 'POST' && pathname === '/email-provider/session') {
      const body = await readRequestBody(req);
      const params = new URLSearchParams(body);
      const action = params.get('action');
      if (action === 'logout') {
        res.writeHead(303, {
          Location: '/',
          'Set-Login': 'logged-out',
          'Set-Cookie': `${SESSION_COOKIE_NAME}=logged-out; Path=/; HttpOnly; SameSite=Lax`,
        });
      } else {
        res.writeHead(303, {
          Location: '/',
          'Set-Login': 'logged-in',
          'Set-Cookie': `${SESSION_COOKIE_NAME}=active; Path=/; HttpOnly; SameSite=Lax`,
        });
      }
      return res.end();
    }

    // -------------------------------------------------------------------------
    // 6a. Toggle `kid` in Mock Issuer EVTs (Test Gmail-style kid-less JWKS loop)
    // -------------------------------------------------------------------------
    if (req.method === 'POST' && pathname === '/email-provider/toggle-kid') {
      includeKidInEvt = !includeKidInEvt;
      res.writeHead(303, { Location: '/' });
      return res.end();
    }

    // -------------------------------------------------------------------------
    // 6b. Toggle Mock Issuer Signing Algorithm (`EdDSA` <-> `ES256`)
    // -------------------------------------------------------------------------
    if (
      req.method === 'POST' &&
      (pathname === '/mock-provider/toggle-alg' || pathname === '/email-provider/toggle-alg')
    ) {
      activeIssuerAlg = activeIssuerAlg === 'ES256' ? 'EdDSA' : 'ES256';
      res.writeHead(303, { Location: '/' });
      return res.end();
    }

    const localAllowedEmails = ['*@localhost.example', '*@localhost', DEFAULT_LOCAL_EMAIL];

    // -------------------------------------------------------------------------
    // 7. Standard EVP Issuance Endpoint: POST /email-verification/issuance
    // -------------------------------------------------------------------------
    if (req.method === 'POST' && pathname === '/email-verification/issuance') {
      const rawBody = await readRequestBody(req);
      const result = handleIssuanceRequest({
        method: 'POST',
        authority: host,
        path: pathname,
        headers: req.headers,
        rawBody,
        isSessionLoggedIn: providerSignedIn,
        allowedEmails: localAllowedEmails,
        issuerOrigin: origin,
        issuerKeyPair: getActiveIssuerKeyPair(),
        includeKidInEvt,
      });
      res.writeHead(result.status, result.headers);
      return res.end(JSON.stringify(result.body));
    }

    // -------------------------------------------------------------------------
    // 8. Browser Simulator Endpoint: POST /api/simulate-browser-issuance
    // -------------------------------------------------------------------------
    if (req.method === 'POST' && pathname === '/api/simulate-browser-issuance') {
      try {
        const rawBody = await readRequestBody(req);
        const { email, nonce, holderAlg } = JSON.parse(rawBody || '{}');
        const sim = simulateBrowserEvpFlow({
          email: email || DEFAULT_LOCAL_EMAIL,
          nonce,
          verifierOrigin: origin,
          issuerOrigin: origin,
          issuerKeyPair: getActiveIssuerKeyPair(),
          holderAlg: holderAlg || activeIssuerAlg,
          isSessionLoggedIn: providerSignedIn,
          allowedEmails: localAllowedEmails,
          includeKidInEvt,
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify(sim));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'simulation_failed', error_description: err.message }));
      }
    }

    // -------------------------------------------------------------------------
    // 9. Relying Party Verifier Page (GET / and POST /)
    // -------------------------------------------------------------------------
    if (pathname === '/') {
      if (req.method === 'GET') {
        const freshNonce = crypto.randomUUID();
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Set-Cookie': `${NONCE_COOKIE_NAME}=${encodeURIComponent(freshNonce)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`,
        });
        return res.end(
          renderVerifierPage({
            origin,
            activeNonce: freshNonce,
            providerSignedIn,
            includeKidInEvt,
            activeIssuerAlg,
            submittedEmail: DEFAULT_LOCAL_EMAIL,
            verificationResult: null,
            errorMsg: '',
            activeTrace: null,
          })
        );
      }

      if (req.method === 'POST') {
        const expectedNonce = cookies[NONCE_COOKIE_NAME] || '';
        const rawFormBody = await readRequestBody(req);
        const formParams = new URLSearchParams(rawFormBody);
        const submittedEmail = (formParams.get('email') || '').trim();
        const rawToken = (formParams.get('token') || '').trim();

        // Issue a new nonce for the next attempt while consuming the old one
        const nextNonce = crypto.randomUUID();

        if (!rawToken) {
          res.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
            'Set-Cookie': `${NONCE_COOKIE_NAME}=${encodeURIComponent(nextNonce)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`,
          });
          return res.end(
            renderVerifierPage({
              origin,
              activeNonce: nextNonce,
              providerSignedIn,
              includeKidInEvt,
              activeIssuerAlg,
              submittedEmail,
              verificationResult: null,
              errorMsg:
                'No EVP token was populated in <input autocomplete="email-verification-token">. ' +
                '1) For offline localhost testing, click "⚡ Simulate Browser EVP Flow". ' +
                '2) For live Chrome 150–156+ testing, you do NOT need an Origin Trial token—enable chrome://flags/#email-verification-protocol (or --enable-features=EmailVerificationProtocol, which is mandatory on Chrome 156 where M150–155 OT tokens do not apply), sign in to @gmail.com or @rowan.fyi, and be sure to exit/blur the email input field (wait for the inline checkmark) before clicking Sign up.',
              activeTrace: null,
            })
          );
        }

        const localDnsOverrides = {
          'localhost.example': origin,
          localhost: origin,
        };

        const boundAddress = server.address();
        const localPort = boundAddress && typeof boundAddress === 'object' ? boundAddress.port : 3000;
        const loopbackFetch = async (urlStr) => {
          const parsed = new URL(urlStr);
          if (parsed.origin === origin) {
            return fetch(`http://127.0.0.1:${localPort}${parsed.pathname}${parsed.search}`, {
              headers: { 'x-evp-original-host': host },
            });
          }
          return fetch(urlStr);
        };

        const verifyOut = await verifyEvpToken({
          rawToken,
          submittedEmail,
          expectedNonce,
          expectedAudience: origin,
          localDnsOverrides,
          enforceExactEmailMatch: true,
          fetchImpl: loopbackFetch,
        });

        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Set-Cookie': `${NONCE_COOKIE_NAME}=${encodeURIComponent(nextNonce)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`,
        });

        return res.end(
          renderVerifierPage({
            origin,
            activeNonce: nextNonce,
            providerSignedIn,
            includeKidInEvt,
            activeIssuerAlg,
            submittedEmail,
            verificationResult: verifyOut.verified ? verifyOut : null,
            errorMsg: verifyOut.verified ? '' : verifyOut.error,
            activeTrace: verifyOut.traceSteps,
          })
        );
      }
    }

    // -------------------------------------------------------------------------
    // 10. Static Demo Assets (index.html, app.js, style.css, traditional.html, explainer.html, glossary.html)
    // -------------------------------------------------------------------------
    const STATIC_FILES = {
      '/index.html': { file: 'index.html', contentType: 'text/html; charset=utf-8' },
      '/app.js': { file: 'app.js', contentType: 'application/javascript; charset=utf-8' },
      '/style.css': { file: 'style.css', contentType: 'text/css; charset=utf-8' },
      '/traditional.html': { file: 'traditional.html', contentType: 'text/html; charset=utf-8' },
      '/traditional.js': { file: 'traditional.js', contentType: 'application/javascript; charset=utf-8' },
      '/explainer.html': { file: 'explainer.html', contentType: 'text/html; charset=utf-8' },
      '/glossary.html': { file: 'glossary.html', contentType: 'text/html; charset=utf-8' },
    };
    if (req.method === 'GET' && STATIC_FILES[pathname]) {
      const entry = STATIC_FILES[pathname];
      const fullPath = path.join(__dirname, entry.file);
      if (fs.existsSync(fullPath)) {
        const content = fs.readFileSync(fullPath);
        res.writeHead(200, {
          'Content-Type': entry.contentType,
          'Cache-Control': 'no-cache',
        });
        return res.end(content);
      }
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  });

  return {
    server,
    issuerKeyPair: ed25519KeyPair,
    p256KeyPair,
    secondaryKeyPair,
  };
}

if (require.main === module) {
  const port = Number(process.env.PORT || 3000);
  const { server } = createEvpLocalhostServer();
  server.listen(port, () => {
    console.log(`======================================================================`);
    console.log(`EVP Localhost Verifier & Mock Issuer running at http://localhost:${port}`);
    console.log(`- Verifier UI:          http://localhost:${port}/`);
    console.log(`- Discovery Metadata:   http://localhost:${port}/.well-known/email-verification`);
    console.log(`- Public JWKS:          http://localhost:${port}/.well-known/vc-public-jwks`);
    console.log(`- Issuance Endpoint:    http://localhost:${port}/email-verification/issuance`);
    console.log(`======================================================================`);
  });
}

module.exports = {
  createEvpLocalhostServer,
};
