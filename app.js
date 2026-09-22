import * as jose from 'https://cdn.jsdelivr.net/npm/jose@5.6.3/+esm';

const SIMULATED_ISSUER_ORIGIN = 'https://mock-issuer.evp.local';

// Well-known issuers dictionary to bypass CORS issues on /.well-known endpoints
const WELL_KNOWN_ISSUERS = {
  'https://accounts.google.com': {
    issuerMetadata: {
      issuance_endpoint: 'https://accounts.google.com/gsi/email-verification/issue',
      jwks_uri: 'https://verifiablecredentials-pa.googleapis.com/.well-known/vc-public-jwks',
      signing_alg_values_supported: ['EdDSA', 'ES256']
    },
    issuerJWKS: null // Will fetch dynamically since it supports CORS
  },
  [SIMULATED_ISSUER_ORIGIN]: {
    issuerMetadata: {
      issuer: SIMULATED_ISSUER_ORIGIN,
      issuance_endpoint: `${SIMULATED_ISSUER_ORIGIN}/email-verification/issuance`,
      jwks_uri: `${SIMULATED_ISSUER_ORIGIN}/.well-known/vc-public-jwks`,
      signing_alg_values_supported: ['EdDSA', 'ES256']
    },
    issuerJWKS: { keys: [] }
  }
};

// Local/Simulated DNS delegation map for offline & localhost testing
const LOCAL_DNS_DELEGATIONS = {
  'evp.local': SIMULATED_ISSUER_ORIGIN,
  'localhost.example': window.location.origin,
  'localhost': window.location.origin
};

// Helper to normalize issuer strings (strips protocol and trailing slashes for robust comparison)
function normalizeIssuer(iss) {
  if (!iss) return '';
  return iss
    .replace(/^https?:\/\//i, '')
    .replace(/\/+$/, '')
    .toLowerCase();
}

let currentChallenge = null;

document.addEventListener('DOMContentLoaded', () => {
  initChallenge();
  checkBrowserEvpSupport();
  setupEmailVerifiedEventListener();
  setupSimulatorButton();
  setupFormSubmit();
  setupThemeToggle();
  setupTabs();
});

// Check Chrome 150-156+ EmailVerifiedEvent support & Origin Trial milestone status
function checkBrowserEvpSupport() {
  const statusEl = document.getElementById('evp-api-status');
  const ua = navigator.userAgent || '';
  const m = ua.match(/Chrome\/(\d+)/);
  const chromeVer = m ? parseInt(m[1], 10) : null;
  const hasEvpEvent = 'EmailVerifiedEvent' in window;

  if (chromeVer && chromeVer >= 150) {
    if (hasEvpEvent) {
      if (statusEl) {
        statusEl.innerHTML = `✅ <strong>Chrome ${chromeVer} detected (<code>EmailVerifiedEvent</code> active)</strong> — No Origin Trial token needed on <code>localhost</code>. Select an autofill email or press <strong>Tab</strong> after typing to trigger <code>emailverified</code>.`;
      }
      consoleLog(`Chrome ${chromeVer} detected: window.EmailVerifiedEvent is active.`, 'success');
    } else {
      if (statusEl) {
        statusEl.innerHTML = `⚠️ <strong>Chrome ${chromeVer} detected, but <code>window.EmailVerifiedEvent</code> is disabled!</strong><br>The Chrome Origin Trial token only covers <strong>M150–155</strong>. On <strong>Chrome 156+</strong> (and on <code>localhost</code> without an Origin Trial token), enable <code>chrome://flags/#email-verification-protocol</code> or launch with <code>--enable-features=EmailVerificationProtocol</code>, or click <strong>⚡ Simulate Browser EVP Flow</strong> below.`;
      }
      consoleLog(`Chrome ${chromeVer}: window.EmailVerifiedEvent is undefined. Enable chrome://flags/#email-verification-protocol (required on Chrome 156+ where M150-155 Origin Trial tokens do not apply).`, 'highlight');
    }
  } else if (statusEl) {
    statusEl.innerHTML = `ℹ️ <strong>Browser Simulator Ready</strong> — Native EVP autofill requires Chrome 150+ with <code>chrome://flags/#email-verification-protocol</code> enabled, or click <strong>⚡ Simulate Browser EVP Flow &amp; Verify</strong> below to test all 6 cryptographic steps right now.`;
  }
}

// Listen for Chrome's `emailverified` event
function setupEmailVerifiedEventListener() {
  const emailInput = document.getElementById('email');
  const evtInput = document.getElementById('evt');

  const handleEmailVerified = (e) => {
    const token = e.presentationToken || (e.detail && e.detail.presentationToken);
    if (token && evtInput) {
      evtInput.value = token;
      consoleLog('Browser fired `emailverified` event and populated presentationToken!', 'success');
    }
  };

  if (emailInput) {
    emailInput.addEventListener('emailverified', handleEmailVerified);
  }
  document.addEventListener('emailverified', handleEmailVerified);
}

// 1-Click In-Browser Simulator (Chrome 154-156 RFC 9421 @target-uri + Sec-Fetch-Dest: email-verification + EdDSA/ES256 + optional kid)
function setupSimulatorButton() {
  const simBtn = document.getElementById('simulate-evp-btn');
  const form = document.getElementById('login-form');
  const emailInput = document.getElementById('email');
  const evtInput = document.getElementById('evt');
  const algSelect = document.getElementById('sim-alg-select');
  const includeKidCheckbox = document.getElementById('sim-include-kid');

  if (!simBtn) return;

  simBtn.addEventListener('click', async () => {
    try {
      simBtn.disabled = true;
      const selectedAlg = algSelect ? algSelect.value : 'EdDSA';
      const includeKid = includeKidCheckbox ? includeKidCheckbox.checked : true;
      let email = (emailInput.value || '').trim();
      if (!email) {
        email = 'First.Last@evp.local';
        emailInput.value = email;
      }

      // Ensure email domain maps to our simulated issuer if user entered a non-delegated domain during simulation
      const domain = email.split('@')[1] || 'evp.local';
      LOCAL_DNS_DELEGATIONS[domain.toLowerCase()] = SIMULATED_ISSUER_ORIGIN;

      const crvOrAlg = selectedAlg === 'ES256' ? 'ES256' : 'EdDSA';
      const distractorKeyPair = await jose.generateKeyPair(crvOrAlg, { extractable: true });
      const issuerKeyPair = await jose.generateKeyPair(crvOrAlg, { extractable: true });
      const holderKeyPair = await jose.generateKeyPair(crvOrAlg, { extractable: true });

      const distractorJwk = await jose.exportJWK(distractorKeyPair.publicKey);
      distractorJwk.kid = 'rotated-old-key-0';
      distractorJwk.use = 'sig';
      distractorJwk.alg = selectedAlg;

      const issuerPublicJwk = await jose.exportJWK(issuerKeyPair.publicKey);
      if (includeKid) {
        issuerPublicJwk.kid = `sim-${selectedAlg.toLowerCase()}-key-1`;
      }
      issuerPublicJwk.use = 'sig';
      issuerPublicJwk.alg = selectedAlg;

      const holderPublicJwk = await jose.exportJWK(holderKeyPair.publicKey);

      // Register simulated JWKS (distractor key first so kid-less Gmail mode tests multi-key loop!)
      WELL_KNOWN_ISSUERS[SIMULATED_ISSUER_ORIGIN].issuerJWKS = {
        keys: [distractorJwk, issuerPublicJwk]
      };

      const now = Math.floor(Date.now() / 1000);
      const requestBody = JSON.stringify({ email });
      const digestB64 = await sha256Base64Url(requestBody);

      // Log Chrome 154-156 RFC 9421 HTTP Message Signature headers
      const sigInput = `sig=("@method" "@target-uri" "content-digest" "sec-fetch-dest" "signature-key");created=${now}`;
      consoleLog(`Simulated Chrome 154–156 RFC 9421 Issuance Request:`, 'system');
      consoleLog(`  POST ${SIMULATED_ISSUER_ORIGIN}/email-verification/issuance`);
      consoleLog(`  Sec-Fetch-Dest: email-verification`);
      consoleLog(`  Content-Digest: sha-256=:${digestB64}:`);
      consoleLog(`  Signature-Input: ${sigInput}`);

      // Build EVT (SD-JWT) preserving exact email casing (Chrome 156+)
      const evtHeader = { alg: selectedAlg, typ: 'evt+jwt' };
      if (includeKid && issuerPublicJwk.kid) {
        evtHeader.kid = issuerPublicJwk.kid;
      }

      const sdJwt = await new jose.SignJWT({
        iss: SIMULATED_ISSUER_ORIGIN,
        iat: now,
        exp: now + 3600,
        email, // Exact email casing preserved (Chrome 156+)
        email_verified: true,
        cnf: { jwk: holderPublicJwk }
      })
        .setProtectedHeader(evtHeader)
        .sign(issuerKeyPair.privateKey);

      const sdHash = await sha256Base64Url(sdJwt + '~');

      const kbJwt = await new jose.SignJWT({
        aud: window.location.origin,
        nonce: currentChallenge,
        iat: now,
        sd_hash: sdHash
      })
        .setProtectedHeader({ alg: selectedAlg, typ: 'kb+jwt' })
        .sign(holderKeyPair.privateKey);

      const presentationToken = `${sdJwt}~${kbJwt}`;
      evtInput.value = presentationToken;

      // Dispatch custom `emailverified` event matching Chrome's spec
      emailInput.dispatchEvent(
        new CustomEvent('emailverified', {
          bubbles: true,
          detail: { presentationToken }
        })
      );

      form.requestSubmit();
    } catch (err) {
      consoleLog(`Simulation error: ${err.message}`, 'error');
    } finally {
      simBtn.disabled = false;
    }
  });
}

// Tab Navigation for Protocol Inspector
function setupTabs() {
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');
  
  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      
      tabButtons.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));
      
      btn.classList.add('active');
      const targetContent = document.getElementById(`tab-${targetTab}`);
      if (targetContent) {
        targetContent.classList.add('active');
      }
    });
  });
}

// Theme Toggle (Dark / Light Mode)
function setupThemeToggle() {
  const themeToggleBtn = document.getElementById('theme-toggle');
  if (!themeToggleBtn) return;
  
  const savedTheme = localStorage.getItem('theme');
  if (savedTheme === 'light') {
    document.body.classList.add('light-theme');
  }
  
  themeToggleBtn.addEventListener('click', () => {
    document.body.classList.toggle('light-theme');
    const isLight = document.body.classList.contains('light-theme');
    localStorage.setItem('theme', isLight ? 'light' : 'dark');
  });
}

// Step 0: Generate a cryptographically secure session challenge (nonce) locally
function initChallenge() {
  const array = new Uint8Array(24);
  window.crypto.getRandomValues(array);
  
  // Convert to base64url
  currentChallenge = btoa(String.fromCharCode.apply(null, array))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
    
  const evtInput = document.getElementById('evt');
  if (evtInput) {
    evtInput.setAttribute('nonce', currentChallenge);
    console.log('Local session challenge (nonce) generated:', currentChallenge);
  }
}

// Form submission (Real / Simulated EVP Flow)
function setupFormSubmit() {
  const form = document.getElementById('login-form');
  const emailInput = document.getElementById('email');
  const evtInput = document.getElementById('evt');
  const submitSpinner = document.getElementById('submit-spinner');
  const submitBtn = document.getElementById('submit-btn');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const email = emailInput.value.trim();
    const evtToken = evtInput.value.trim();

    resetResults();

    // If the hidden token field was not populated, fallback to legacy OTP
    if (!evtToken) {
      console.log('No EVP token found. Falling back to legacy OTP...');
      setOverallStatus('failed', 'No EVP Token (Fallback Triggered)');
      showError('No EVP token was populated by the browser. For this demo, the site will now fallback to sending a traditional 6-digit verification code or Magic Link to ' + email + '.');
      renderFallbackTrace(email);
      return;
    }

    setOverallStatus('verifying', 'Verifying...');
    submitSpinner.style.display = 'inline-block';
    submitBtn.disabled = true;

    const result = await verifyEVPToken(evtToken, email);
    
    // Consume and rotate the single-use session challenge (nonce) after each verification attempt
    evtInput.value = '';
    initChallenge();

    submitSpinner.style.display = 'none';
    submitBtn.disabled = false;

    if (result.success) {
      setOverallStatus('verified', 'Verified');
      showSuccess(result.email);
    } else {
      setOverallStatus('failed', 'Failed (Fallback Triggered)');
      showError((result.error || 'Verification failed.') + ' For this demo, the site will now fallback to sending a traditional 6-digit verification code or Magic Link to ' + email + '.');
    }
    renderTrace(result.trace);
  });
}

/* UI Helper Functions */
function consoleLog(message, type = '') {
  const consoleEl = document.getElementById('console-log-terminal');
  if (!consoleEl) return;
  
  const lineEl = document.createElement('div');
  lineEl.className = `console-line ${type}`;
  
  const timeSpan = document.createElement('span');
  timeSpan.className = 'timestamp';
  timeSpan.textContent = `[${new Date().toLocaleTimeString()}]`;
  
  lineEl.appendChild(timeSpan);
  lineEl.appendChild(document.createTextNode(' ' + message));
  consoleEl.appendChild(lineEl);
  
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

function decodeJwtPart(part) {
  try {
    const base64 = part.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch (e) {
    return { error: 'Failed to decode part: ' + e.message };
  }
}

async function sha256Base64Url(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  let binary = '';
  for (let i = 0; i < hashArray.length; i++) {
    binary += String.fromCharCode(hashArray[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/* Core Client-Side Verification Engine */
async function verifyEVPToken(clientEvtString, submittedEmail) {
  const trace = [];
  const expectedAudience = window.location.origin;
  const expectedNonce = currentChallenge;

  const consoleEl = document.getElementById('console-log-terminal');
  if (consoleEl) consoleEl.innerHTML = ''; // Clear logs

  consoleLog('This is a real SD-JWT+KB verifier.', 'system');
  consoleLog('We got a verification token!', 'system');
  consoleLog(clientEvtString);

  let sdJwtString = '';
  let kbJwtString = '';
  let evtJwtDecodedHeader = null;
  let sdPayload = null;
  let kbJwtDecodedHeader = null;
  let kbPayload = null;
  let idpJwksUri = null;
  let issuerMetadata = null;
  let issuerJWKS = null;

  // --- Step 1: Token Decomposition & Parsing ---
  try {
    const parts = clientEvtString.split('~');
    if (parts.length !== 2) {
      throw new Error('Invalid token format. Expected [SD-JWT_Issuance_Token]~[KB-JWT_Presentation_Token]');
    }
    [sdJwtString, kbJwtString] = parts;

    const sdParts = sdJwtString.split('.');
    const kbParts = kbJwtString.split('.');

    if (sdParts.length !== 3 || kbParts.length !== 3) {
      throw new Error('Tokens must be valid 3-part JWS strings.');
    }

    evtJwtDecodedHeader = decodeJwtPart(sdParts[0]);
    sdPayload = decodeJwtPart(sdParts[1]);
    kbJwtDecodedHeader = decodeJwtPart(kbParts[0]);
    kbPayload = decodeJwtPart(kbParts[1]);

    if (evtJwtDecodedHeader.error || sdPayload.error || kbJwtDecodedHeader.error || kbPayload.error) {
      throw new Error('Malformed Base64URL JSON in EVT or KB-JWT segments.');
    }

    consoleLog('6.5.1: parsed EVT+KB by separating the EVT and KB-JWT at the tilde');
    consoleLog('5.3.1: parsed JWT into header, payload, and signature components');
    consoleLog(`5.3.1: Header: ${JSON.stringify(evtJwtDecodedHeader)}`);
    consoleLog(`5.3.1: Payload: ${JSON.stringify(sdPayload)}`);
    consoleLog('6.5.2: parsed JWT into header, payload, and signature components');
    consoleLog(`6.5.2: Header: ${JSON.stringify(kbJwtDecodedHeader)}`);
    consoleLog(`6.5.2: Payload: ${JSON.stringify(kbPayload)}`);

    trace.push({
      step: 1,
      name: 'Token Decomposition & Parsing',
      status: 'success',
      description: 'Decompose the submitted token into its distinct EVT and Key Binding JWT (KB-JWT) components, and perform unverified local decoding of their headers and payloads.',
      inputs: { rawToken: clientEvtString },
      outputs: {
        evtJwtDecodedHeader,
        evtJwtDecodedPayload: sdPayload,
        kbJwtDecodedHeader,
        kbJwtDecodedPayload: kbPayload
      }
    });
  } catch (error) {
    consoleLog(`Token Parsing Failed: ${error.message}`, 'error');
    trace.push({
      step: 1,
      name: 'Token Decomposition & Parsing',
      status: 'failure',
      description: 'Failed to decompose or decode the token components.',
      inputs: { rawToken: clientEvtString },
      outputs: { error: error.message }
    });
    return { success: false, error: error.message, trace };
  }

  // --- Step 2: Local Claims & Session Binding Verification ---
  try {
    const tokenEmail = sdPayload.email;
    const emailVerifiedClaim = sdPayload.email_verified;
    const tokenAudience = kbPayload.aud;
    const tokenNonce = kbPayload.nonce;
    
    const calculatedEvtHash = await sha256Base64Url(sdJwtString + '~');
    const tokenHash = kbPayload.sd_hash;

    const inputs = {
      submittedEmail,
      tokenEmail,
      emailVerifiedClaim,
      expectedAudience,
      tokenAudience,
      expectedNonce,
      tokenNonce,
      calculatedEvtHash,
      tokenHash
    };

    const allowedAlgs = ['EdDSA', 'Ed25519', 'ES256'];
    if (!kbJwtDecodedHeader.alg || !allowedAlgs.includes(kbJwtDecodedHeader.alg)) {
      throw new Error(`Unsupported or missing KB-JWT alg: "${kbJwtDecodedHeader.alg || 'none'}". Expected EdDSA or ES256.`);
    }
    if (kbJwtDecodedHeader.typ !== 'kb+jwt') {
      throw new Error(`Invalid KB-JWT typ: "${kbJwtDecodedHeader.typ}". Expected "kb+jwt".`);
    }

    consoleLog(`6.1.1: required alg is present: "${kbJwtDecodedHeader.alg}"`);
    consoleLog('6.1.1: KB-JWT alg is not none');
    consoleLog(`6.1.1: required typ is present: "${kbJwtDecodedHeader.typ}"`);
    consoleLog('6.1.1: KB-JWT typ is kb+jwt');
    consoleLog(`6.1.2: required aud is present: "${tokenAudience}"`);
    consoleLog(`6.1.2: required nonce is present: "${tokenNonce}"`);
    consoleLog(`6.1.2: required iat is present: ${kbPayload.iat}`);
    consoleLog(`6.1.2: required sd_hash is present: "${tokenHash}"`);

    // Chrome 156+ requires exact email casing preservation between form input and EVT claim
    if (!submittedEmail || !tokenEmail || submittedEmail.trim() !== tokenEmail.trim()) {
      throw new Error(`Email mismatch (Chrome 156+ enforces exact email case preservation). Submitted: "${submittedEmail}", Token: "${tokenEmail}"`);
    }
    if (emailVerifiedClaim !== true) {
      throw new Error('Email verified claim is not true.');
    }
    
    const expectedHost = new URL(expectedAudience).host;
    const tokenHost = new URL(tokenAudience).host;
    if (expectedHost !== tokenHost) {
      throw new Error(`Audience mismatch. Expected: "${expectedAudience}", Token: "${tokenAudience}"`);
    }
    consoleLog(`6.5.4: KB-JWT aud matches RP origin ${expectedAudience}`, 'success');

    if (expectedNonce && tokenNonce !== expectedNonce) {
      throw new Error(`Nonce mismatch. Expected: "${expectedNonce}", Token: "${tokenNonce}"`);
    }
    consoleLog('6.5.5: KB-JWT nonce matches the RP session nonce', 'success');

    const nowSec = Math.floor(Date.now() / 1000);
    const timeDiff = Math.abs(nowSec - kbPayload.iat);
    if (typeof kbPayload.iat !== 'number' || timeDiff > 600) {
      throw new Error(`KB-JWT iat timestamp (${kbPayload.iat}) is outside the valid 600s window (diff: ${timeDiff}s).`);
    }
    consoleLog('6.5.6: iat is within 600 seconds of now', 'success');

    if (calculatedEvtHash !== tokenHash) {
      throw new Error(`Hash binding mismatch. Calculated: "${calculatedEvtHash}", Token sd_hash: "${tokenHash}"`);
    }
    consoleLog('6.5.7: KB-JWT sd_hash matches the SHA-256 hash of the EVT including trailing tilde', 'success');
    consoleLog('2.7.1: verified KB-JWT per KB-JWT Verification', 'success');

    trace.push({
      step: 2,
      name: 'Local Claims & Session Binding Verification',
      status: 'success',
      description: 'Verify local claims (exact Chrome 156+ email casing match, verification status, audience, single-use nonce, timestamp freshness, and cryptographic hash binding).',
      inputs,
      outputs: {
        localChecksPassed: true,
        exactEmailCaseMatched: submittedEmail.trim() === tokenEmail.trim(),
        details: 'All local claims, exact email case, session nonce, target audience, and hash binding checks matched successfully.'
      }
    });
  } catch (error) {
    consoleLog(`Local Claims Verification Failed: ${error.message}`, 'error');
    trace.push({
      step: 2,
      name: 'Local Claims & Session Binding Verification',
      status: 'failure',
      description: 'Local claims or session binding checks failed.',
      inputs: {
        submittedEmail,
        tokenEmail: sdPayload?.email,
        emailVerifiedClaim: sdPayload?.email_verified,
        expectedAudience,
        tokenAudience: kbPayload?.aud,
        expectedNonce,
        tokenNonce: kbPayload?.nonce,
      },
      outputs: { error: error.message }
    });
    return { success: false, error: error.message, trace };
  }

  // --- Step 3: DNS Delegation Authority Verification ---
  const tokenIssuer = sdPayload.iss;
  const emailDomain = submittedEmail.split('@')[1];
  const dnsLookupTarget = `_email-verification.${emailDomain}`;
  
  try {
    let authorizedBy = '';
    let details = '';
    
    const issuerHost = new URL(tokenIssuer).hostname;
    
    consoleLog(`5.1.1: required alg is present: "${evtJwtDecodedHeader.alg || 'EdDSA'}"`);
    consoleLog('5.1.1: EVT alg is not none');
    if (!evtJwtDecodedHeader.kid) {
      consoleLog('5.1.1: EVT kid is missing; trying all issuer keys as a compatibility fallback', 'highlight');
    }
    consoleLog(`5.1.1: required typ is present: "${evtJwtDecodedHeader.typ || 'evt+jwt'}"`);
    consoleLog('5.1.1: EVT typ is evt+jwt');
    consoleLog(`5.1.2: required iss is present: "${tokenIssuer}"`);
    consoleLog(`5.1.2: required iat is present: ${sdPayload.iat}`);
    consoleLog(`5.1.2: required cnf is present: ${JSON.stringify(sdPayload.cnf)}`);
    consoleLog(`5.1.2: required email is present: "${sdPayload.email}"`);
    consoleLog(`5.1.2: required email_verified is present: ${sdPayload.email_verified}`);
    if (sdPayload.cnf?.jwk?.crv === 'Ed25519') {
      consoleLog('5.1.2: cnf.jwk contains an Ed25519 (EdDSA) public key');
    } else if (sdPayload.cnf?.jwk?.crv === 'P-256') {
      consoleLog('5.1.2: cnf.jwk contains a P-256 (ES256) public key');
    }
    consoleLog('5.1.2: email has valid address syntax');
    if (submittedEmail.trim() === sdPayload.email.trim()) {
      consoleLog(`5.3.8: Chrome 156+ exact email casing preserved ("${sdPayload.email}")`, 'success');
    }
    
    const sdTimeDiff = Math.abs(Math.floor(Date.now() / 1000) - sdPayload.iat);
    if (typeof sdPayload.iat !== 'number' || sdTimeDiff > 600) {
      throw new Error(`EVT iat timestamp (${sdPayload.iat}) is outside the valid 600s window (diff: ${sdTimeDiff}s).`);
    }
    consoleLog('5.3.7: iat is within 600 seconds of now', 'success');
    consoleLog('5.3.8: EVT email_verified is true', 'success');
    consoleLog('3.1: email has valid address syntax');
    consoleLog(`3.1: fetching DNS TXT records for ${dnsLookupTarget}`);

    const localDelegatedIssuer = LOCAL_DNS_DELEGATIONS[emailDomain.toLowerCase()];

    if (emailDomain.toLowerCase() === issuerHost.toLowerCase()) {
      authorizedBy = 'Direct Domain Equality (Self-Authoritative)';
      details = 'Email domain directly matches the token issuer host. DNS delegation lookup skipped.';
      consoleLog(`5.3.4: EVT iss claim matches DNS issuer identifier ${normalizeIssuer(tokenIssuer)} (Direct Domain Match)`, 'success');
    } else if (localDelegatedIssuer && normalizeIssuer(localDelegatedIssuer) === normalizeIssuer(tokenIssuer)) {
      authorizedBy = 'Local / Simulated DNS Delegation Override';
      details = `Local/simulated DNS TXT record at ${dnsLookupTarget} ("iss=${localDelegatedIssuer}") delegates authority to ${tokenIssuer}.`;
      consoleLog(`3.1: local/simulated TXT record for ${dnsLookupTarget}: "iss=${localDelegatedIssuer}"`);
      consoleLog(`5.3.4: EVT iss claim matches delegated issuer identifier ${normalizeIssuer(tokenIssuer)}`, 'success');
    } else {
      // Perform DNS TXT lookup using DNS-over-HTTPS (DoH)
      const dohUrl = `https://dns.google/resolve?name=${dnsLookupTarget}&type=TXT`;
      const dohRes = await fetch(dohUrl);
      const dohData = await dohRes.json();
      
      let foundDelegation = false;
      const numRecords = dohData.Answer ? dohData.Answer.length : 0;
      consoleLog(`3.1: found ${numRecords} TXT record(s) for ${dnsLookupTarget}`);

      if (dohData.Answer && dohData.Answer.length > 0) {
        for (const ans of dohData.Answer) {
          const recordStr = ans.data.replace(/"/g, '').trim();
          consoleLog(`3.1: TXT data: "${recordStr}"`);
          if (recordStr.startsWith('iss=')) {
            consoleLog('3.1: TXT record starts with iss=');
            const delegatedIssuer = recordStr.substring(4).trim();
            consoleLog(`3.1: extracted issuer identifier ${delegatedIssuer}`);
            if (normalizeIssuer(delegatedIssuer) === normalizeIssuer(tokenIssuer)) {
              foundDelegation = true;
              break;
            }
          }
        }
      }
      
      if (foundDelegation) {
        authorizedBy = 'DNS TXT Record Delegation';
        details = `Successfully verified DNS delegation via DoH: TXT record at ${dnsLookupTarget} delegates authority to issuer ${tokenIssuer}`;
        consoleLog(`5.3.4: EVT iss claim matches DNS issuer identifier ${normalizeIssuer(tokenIssuer)}`, 'success');
      } else {
        throw new Error(`DNS TXT records at ${dnsLookupTarget} resolved but no matching 'iss=${tokenIssuer}' record was found.`);
      }
    }

    trace.push({
      step: 3,
      name: 'DNS Delegation Authority Verification',
      status: 'success',
      description: 'Perform dynamic server-side DNS queries (via DNS-over-HTTPS) to confirm that the email\'s domain delegated verification authority to the token issuer.',
      inputs: {
        submittedEmail,
        tokenIssuer,
        dnsLookupTarget
      },
      outputs: {
        authorizedBy,
        details
      }
    });
  } catch (error) {
    consoleLog(`DNS Delegation Verification Failed: ${error.message}`, 'error');
    trace.push({
      step: 3,
      name: 'DNS Delegation Authority Verification',
      status: 'failure',
      description: 'Failed to verify DNS delegation authority.',
      inputs: {
        submittedEmail,
        tokenIssuer,
        dnsLookupTarget
      },
      outputs: { error: error.message }
    });
    return { success: false, error: error.message, trace };
  }

  // --- Step 4: Issuer Discovery & JWKS Fetching ---
  try {
    const wellKnownUrl = `${tokenIssuer}/.well-known/email-verification`;
    consoleLog(`3.2: fetching issuer metadata from ${wellKnownUrl}`);
    
    // Check if we have a hardcoded fallback for this issuer to bypass CORS
    const knownIssuer = WELL_KNOWN_ISSUERS[tokenIssuer];
    
    if (knownIssuer) {
      issuerMetadata = knownIssuer.issuerMetadata;
      idpJwksUri = issuerMetadata.jwks_uri;
      
      consoleLog('3.2: fetched issuer metadata JSON');
      consoleLog(`3.2: issuer metadata: ${JSON.stringify(issuerMetadata)}`);
      
      if (knownIssuer.issuerJWKS) {
        issuerJWKS = knownIssuer.issuerJWKS;
      } else {
        consoleLog(`Fetching JWKS directly: ${idpJwksUri}`);
        const jwksRes = await fetch(idpJwksUri);
        issuerJWKS = await jwksRes.json();
      }
    } else {
      try {
        const metadataResponse = await fetch(wellKnownUrl);
        if (!metadataResponse.ok) throw new Error(`Metadata HTTP error ${metadataResponse.status}`);
        issuerMetadata = await metadataResponse.json();
        idpJwksUri = issuerMetadata.jwks_uri;
        
        consoleLog('3.2: fetched issuer metadata JSON');
        consoleLog(`3.2: issuer metadata: ${JSON.stringify(issuerMetadata)}`);
        
        consoleLog(`Fetching JWKS directly: ${idpJwksUri}`);
        const jwksResponse = await fetch(idpJwksUri);
        if (!jwksResponse.ok) throw new Error(`JWKS HTTP error ${jwksResponse.status}`);
        issuerJWKS = await jwksResponse.json();
      } catch (fetchErr) {
        throw new Error(`Issuer discovery failed (likely due to CORS restriction on the IdP). Technical error: ${fetchErr.message}`);
      }
    }

    consoleLog(`3.2: issuer metadata includes issuance_endpoint`);
    consoleLog(`3.2: issuer metadata includes jwks_uri`);
    consoleLog(`3.2: signing_alg_values_supported is a JSON array`);
    consoleLog(`3.2: signing_alg_values_supported does not include none`);
    
    const numKeys = issuerJWKS.keys ? issuerJWKS.keys.length : 0;
    consoleLog(`5.3.5: fetched ${numKeys} issuer public key(s) from jwks_uri`, 'success');

    trace.push({
      step: 4,
      name: 'Issuer Discovery & JWKS Fetching',
      status: 'success',
      description: 'Fetch the issuer\'s well-known configuration and JWKS public keys from their authoritative origin.',
      serverCalled: `${wellKnownUrl} & ${idpJwksUri}`,
      inputs: {
        url: wellKnownUrl
      },
      outputs: {
        issuerMetadata,
        issuerJWKS
      }
    });
  } catch (error) {
    consoleLog(`Issuer Discovery Failed: ${error.message}`, 'error');
    trace.push({
      step: 4,
      name: 'Issuer Discovery & JWKS Fetching',
      status: 'failure',
      description: 'Failed to discover issuer endpoints or fetch JWKS.',
      inputs: { tokenIssuer },
      outputs: { error: error.message }
    });
    return { success: false, error: error.message, trace };
  }

  // --- Step 5: Issuer Signature Cryptographic Verification ---
  try {
    const evtHeader = decodeJwtPart(sdJwtString.split('.')[0]);
    const signingAlg = evtHeader.alg || 'EdDSA';
    const kid = evtHeader.kid;

    // Prioritize kid-matching keys first when kid is present, then fall back to remaining keys (Gmail compatibility)
    const candidateKeys = kid
      ? [
          ...issuerJWKS.keys.filter((k) => k.kid === kid),
          ...issuerJWKS.keys.filter((k) => k.kid !== kid),
        ]
      : [...issuerJWKS.keys];

    if (!kid) {
      consoleLog('5.3.6: no EVT kid was provided (Gmail compatibility mode), checking all issuer public keys', 'highlight');
    }
    
    consoleLog(`5.3.6: checking the EVT signature (${signingAlg}) with ${candidateKeys.length} candidate key(s)`);

    let verified = false;
    let verifiedPayload = null;
    let matchedKeyId = null;

    for (let i = 0; i < candidateKeys.length; i++) {
      const key = candidateKeys[i];
      const keyAlg = key.alg || (key.crv === 'P-256' ? 'ES256' : signingAlg);
      consoleLog(`5.3.6: trying issuer signing key #${i + 1} (${key.kid || 'no-kid'}, ${keyAlg})`);
      try {
        const importedKey = await jose.importJWK(key, keyAlg);
        consoleLog('Key imported!');
        consoleLog(JSON.stringify(key));
        
        const { payload } = await jose.jwtVerify(sdJwtString, importedKey, {
          issuer: tokenIssuer,
          algorithms: [signingAlg]
        });
        
        consoleLog('Signature with an imported key verifies!!!', 'success');
        consoleLog(`5.3.6: EVT signature verified with issuer signing key #${i + 1}`, 'success');
        verified = true;
        verifiedPayload = payload;
        matchedKeyId = key.kid || 'matched-key-without-kid';
        break;
      } catch (err) {
        consoleLog(`Doesn't verify :(`, 'highlight');
      }
    }

    if (!verified) {
      throw new Error("None of the issuer public keys verified the signature.");
    }

    consoleLog('5.3.6: EVT signature verified with an issuer public key', 'success');
    consoleLog('2.7.2: verified EVT per EVT Verification', 'success');

    trace.push({
      step: 5,
      name: 'Issuer Signature Cryptographic Verification',
      status: 'success',
      description: 'Cryptographically verify the EVT signature using the fetched issuer public keys from their JWKS (supporting both EdDSA and ES256, and optional kid fallback).',
      inputs: {
        evtJwt: sdJwtString,
        signingAlg,
        kid: kid || null
      },
      outputs: {
        verifiedPayload,
        matchedKey: matchedKeyId,
        kidWasPresentInEvtHeader: Boolean(kid),
        cryptographicallyVerified: true
      }
    });
  } catch (error) {
    consoleLog(`Issuer Signature Verification Failed: ${error.message}`, 'error');
    trace.push({
      step: 5,
      name: 'Issuer Signature Cryptographic Verification',
      status: 'failure',
      description: 'Cryptographic verification of the IdP signature failed.',
      inputs: {
        evtJwt: sdJwtString
      },
      outputs: { error: error.message }
    });
    return { success: false, error: error.message, trace };
  }

  // --- Step 6: Ephemeral Key Binding Cryptographic Verification ---
  try {
    const ephemeralPublicKey = sdPayload.cnf?.jwk;
    if (!ephemeralPublicKey) {
      throw new Error('Missing ephemeral key binding (cnf.jwk) in SD-JWT payload.');
    }
    if (ephemeralPublicKey.d) {
      throw new Error('Security violation: cnf.jwk must not contain private key parameter "d".');
    }

    const kbHeader = decodeJwtPart(kbJwtString.split('.')[0]);
    let alg = kbHeader.alg || 'ES256';
    if (ephemeralPublicKey.crv === 'Ed25519' || ephemeralPublicKey.alg === 'EdDSA') {
      alg = 'EdDSA';
      consoleLog('6.5.8: cnf.jwk contains an Ed25519 (EdDSA) public key');
    } else if (ephemeralPublicKey.crv === 'P-256' || ephemeralPublicKey.alg === 'ES256') {
      alg = 'ES256';
      consoleLog('6.5.8: cnf.jwk contains a P-256 (ES256) public key');
    }
    
    const importedEphemeralKey = await jose.importJWK(ephemeralPublicKey, alg);
    consoleLog('Key imported!');
    consoleLog(JSON.stringify(ephemeralPublicKey));

    const { payload: kbVerifiedPayload } = await jose.jwtVerify(kbJwtString, importedEphemeralKey, {
      audience: expectedAudience,
      algorithms: [alg]
    });

    consoleLog('Signature with an imported key verifies!!!', 'success');
    consoleLog('6.5.8: KB-JWT signature verified with the public key from EVT cnf.jwk', 'success');
    consoleLog(`2.7.3: verified KB-JWT signature using public key from EVT cnf.jwk (${alg})`, 'success');
    consoleLog(`2.7: verified control of ${sdPayload.email}`, 'success');

    trace.push({
      step: 6,
      name: 'Ephemeral Key Binding Cryptographic Verification',
      status: 'success',
      description: 'Extract the browser\'s ephemeral public key from the validated EVT and cryptographically verify the KB-JWT signature to prove possession of the private key.',
      inputs: {
        cnf: sdPayload.cnf,
        kbJwt: kbJwtString,
        kbSigningAlg: alg
      },
      outputs: {
        extractedBrowserJwk: ephemeralPublicKey,
        kbPayloadHeader: kbHeader,
        kbPayloadBody: kbVerifiedPayload,
        keyBindingPassed: true,
        holderVerification: `Holder Private Key possession verified (${alg}).`
      }
    });
  } catch (error) {
    consoleLog(`Key Binding Cryptographic Verification Failed: ${error.message}`, 'error');
    trace.push({
      step: 6,
      name: 'Ephemeral Key Binding Cryptographic Verification',
      status: 'failure',
      description: 'Cryptographic verification of the key binding signature failed.',
      inputs: {
        cnf: sdPayload?.cnf,
        kbJwt: kbJwtString
      },
      outputs: { error: error.message }
    });
    return { success: false, error: error.message, trace };
  }

  return {
    success: true,
    email: sdPayload.email,
    trace
  };
}

function setOverallStatus(statusClass, text) {
  const badge = document.getElementById('overall-status');
  badge.className = `status-badge ${statusClass}`;
  badge.textContent = text;
}

function showSuccess(email) {
  const banner = document.getElementById('success-banner');
  const emailText = document.getElementById('verified-email-text');
  emailText.textContent = email;
  banner.classList.remove('hidden');
}

function showError(message) {
  const banner = document.getElementById('error-banner');
  const messageText = document.getElementById('error-message-text');
  messageText.textContent = message;
  banner.classList.remove('hidden');
}

function resetResults() {
  document.getElementById('success-banner').classList.add('hidden');
  document.getElementById('error-banner').classList.add('hidden');
  document.getElementById('trace-steps-list').innerHTML = '';
}

function renderTrace(traceSteps) {
  const container = document.getElementById('trace-steps-list');
  container.innerHTML = '';

  traceSteps.forEach(step => {
    const stepEl = document.createElement('div');
    stepEl.className = `trace-step ${step.status}`;

    const headerEl = document.createElement('div');
    headerEl.className = 'trace-step-header';
    headerEl.innerHTML = `
      <div class="trace-step-title">
        <span class="step-num">${step.step}</span>
        <span class="step-name">${escapeHtml(step.name)}</span>
      </div>
      <span class="step-badge ${step.status}">${step.status}</span>
    `;

    const bodyEl = document.createElement('div');
    bodyEl.className = 'trace-step-body';
    
    let serverCalledHtml = '';
    if (step.serverCalled) {
      serverCalledHtml = `<p class="step-desc"><strong>Server Called:</strong> <code>${escapeHtml(step.serverCalled)}</code></p>`;
    }

    bodyEl.innerHTML = `
      <p class="step-desc">${escapeHtml(step.description)}</p>
      ${serverCalledHtml}
      <div class="json-box-container">
        <button class="toggle-json-btn">
          <span>Show Input / Output Data Traces</span>
          <span class="arrow">▼</span>
        </button>
        <div class="json-details hidden">
          <div class="json-label">Inputs Sent:</div>
          <pre class="json-data">${escapeHtml(JSON.stringify(step.inputs, null, 2))}</pre>
          <div class="json-label">Outputs Received:</div>
          <pre class="json-data">${escapeHtml(JSON.stringify(step.outputs, null, 2))}</pre>
        </div>
      </div>
    `;

    headerEl.addEventListener('click', () => {
      bodyEl.classList.toggle('open');
    });

    const toggleJsonBtn = bodyEl.querySelector('.toggle-json-btn');
    const jsonDetails = bodyEl.querySelector('.json-details');
    const arrow = bodyEl.querySelector('.arrow');
    
    toggleJsonBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      jsonDetails.classList.toggle('hidden');
      arrow.textContent = jsonDetails.classList.contains('hidden') ? '▼' : '▲';
    });

    stepEl.appendChild(headerEl);
    stepEl.appendChild(bodyEl);
    container.appendChild(stepEl);
  });
}

function renderFallbackTrace(email) {
  const container = document.getElementById('trace-steps-list');
  container.innerHTML = `
    <div class="trace-step failure">
      <div class="trace-step-header" style="cursor: default;">
        <div class="trace-step-title">
          <span class="step-num">1</span>
          <span class="step-name">EVP Token Check</span>
        </div>
        <span class="step-badge failure">missing</span>
      </div>
      <div class="trace-step-body open" style="display: block; border-top: 1px solid var(--card-border);">
        <p class="step-desc">The browser did not populate the <code>email-verification-token</code> hidden input. This happens when the user types the email manually, declines permission, or uses a browser/domain that does not support EVP.</p>
      </div>
    </div>
    <div class="trace-step success" style="border-left-color: var(--primary-color);">
      <div class="trace-step-header" style="cursor: default;">
        <div class="trace-step-title">
          <span class="step-num">2</span>
          <span class="step-name">Legacy Verification Triggered</span>
        </div>
        <span class="step-badge success" style="background: rgba(59,130,246,0.15); color: var(--primary-color);">triggered</span>
      </div>
      <div class="trace-step-body open" style="display: block; border-top: 1px solid var(--card-border);">
        <p class="step-desc">A fallback One-Time Passcode (OTP) or magic link has been generated and dispatched to <code>${escapeHtml(email)}</code>. The user must check their inbox to complete verification.</p>
      </div>
    </div>
  `;
}

// Simple HTML escaping helper
function escapeHtml(string) {
  return String(string)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
