import * as jose from 'https://cdn.jsdelivr.net/npm/jose@5.6.3/+esm';

// Well-known issuers dictionary to bypass CORS issues on /.well-known endpoints
const WELL_KNOWN_ISSUERS = {
  'https://accounts.google.com': {
    issuerMetadata: {
      issuance_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
      jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs',
      signing_alg_values_supported: ['RS256', 'ES256']
    },
    issuerJWKS: null // Will fetch dynamically since Google JWKS supports CORS
  }
};


let currentChallenge = null;

document.addEventListener('DOMContentLoaded', () => {
  initChallenge();
  setupTabs();
  setupFormSubmit();
  setupManualVerify();
});

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

// Tab navigation logic
function setupTabs() {
  const tabs = document.querySelectorAll('.tab-btn');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      
      tab.classList.add('active');
      const targetContent = document.getElementById(tab.dataset.tab);
      targetContent.classList.add('active');
    });
  });
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

    // Phase 2: If the hidden token field was not populated, fallback to legacy OTP
    if (!evtToken) {
      console.log('No EVP token found. Falling back to legacy OTP...');
      setOverallStatus('failed', 'No EVP Token (Fallback Triggered)');
      showError('No EVP token was populated by the browser. The site will now fallback to sending a traditional 6-digit verification code to ' + email + '.');
      renderFallbackTrace(email);
      return;
    }

    setOverallStatus('verifying', 'Verifying...');
    submitSpinner.style.display = 'inline-block';
    submitBtn.disabled = true;

    const result = await verifyEVPToken(evtToken, email);
    
    submitSpinner.style.display = 'none';
    submitBtn.disabled = false;

    if (result.success) {
      setOverallStatus('verified', 'Verified');
      showSuccess(result.email);
    } else {
      setOverallStatus('failed', 'Failed');
      showError(result.error || 'Verification failed.');
    }
    renderTrace(result.trace);
  });
}

// Manual Token verification submit
function setupManualVerify() {
  const verifyBtn = document.getElementById('manual-verify-btn');
  const emailInput = document.getElementById('manual-email');
  const tokenInput = document.getElementById('manual-token');
  const spinner = document.getElementById('manual-spinner');

  verifyBtn.addEventListener('click', async () => {
    const email = emailInput.value.trim();
    const evtToken = tokenInput.value.trim();

    if (!email || !evtToken) {
      alert('Please enter both the email address and the raw EVP token.');
      return;
    }

    resetResults();
    setOverallStatus('verifying', 'Verifying...');
    spinner.style.display = 'inline-block';
    verifyBtn.disabled = true;

    const result = await verifyEVPToken(evtToken, email);
    
    spinner.style.display = 'none';
    verifyBtn.disabled = false;

    if (result.success) {
      setOverallStatus('verified', 'Verified');
      showSuccess(result.email);
    } else {
      setOverallStatus('failed', 'Failed');
      showError(result.error || 'Verification failed.');
    }
    renderTrace(result.trace);
  });
}

/* Core Client-Side Verification Engine */

// Helper to base64url decode without verification
function decodeJwtPart(part) {
  try {
    const binary = atob(part.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(binary);
  } catch (e) {
    return { error: 'Failed to decode part: ' + e.message };
  }
}

// Helper to calculate base64url SHA-256 hash in the browser
async function sha256Base64Url(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashString = String.fromCharCode.apply(null, hashArray);
  return btoa(hashString)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

async function verifyEVPToken(clientEvtString, submittedEmail) {
  const trace = [];
  const expectedAudience = window.location.origin;
  const expectedNonce = currentChallenge;

  let sdJwtString = '';
  let kbJwtString = '';
  let sdPayload = null;
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

    const evtJwtDecodedHeader = decodeJwtPart(sdParts[0]);
    sdPayload = decodeJwtPart(sdParts[1]);
    const kbJwtDecodedHeader = decodeJwtPart(kbParts[0]);
    kbPayload = decodeJwtPart(kbParts[1]);

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

    if (!submittedEmail || submittedEmail.trim().toLowerCase() !== tokenEmail.trim().toLowerCase()) {
      throw new Error(`Email mismatch. Submitted: "${submittedEmail}", Token: "${tokenEmail}"`);
    }
    if (emailVerifiedClaim !== true) {
      throw new Error('Email verified claim is not true.');
    }
    
    const expectedHost = new URL(expectedAudience).host;
    const tokenHost = new URL(tokenAudience).host;
    if (expectedHost !== tokenHost) {
      throw new Error(`Audience mismatch. Expected: "${expectedAudience}", Token: "${tokenAudience}"`);
    }

    if (expectedNonce && tokenNonce !== expectedNonce) {
      throw new Error(`Nonce mismatch. Expected: "${expectedNonce}", Token: "${tokenNonce}"`);
    }

    if (calculatedEvtHash !== tokenHash) {
      throw new Error(`Hash binding mismatch. Calculated: "${calculatedEvtHash}", Token sd_hash: "${tokenHash}"`);
    }

    trace.push({
      step: 2,
      name: 'Local Claims & Session Binding Verification',
      status: 'success',
      description: 'Verify local, non-cryptographic claims (email match, verification status, audience, nonce, and cryptographic hash binding) to fail fast before doing network or crypto operations.',
      inputs,
      outputs: {
        localChecksPassed: true,
        details: 'All local claims, session nonce, target audience, and hash binding checks matched successfully.'
      }
    });
  } catch (error) {
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
    
    if (emailDomain.toLowerCase() === issuerHost.toLowerCase()) {
      authorizedBy = 'Direct Domain Equality (Self-Authoritative)';
      details = 'Email domain directly matches the token issuer host. DNS delegation lookup skipped.';
    } else {
      // Perform DNS TXT lookup using DNS-over-HTTPS (DoH)
      const dohUrl = `https://dns.google/resolve?name=${dnsLookupTarget}&type=TXT`;
      const dohRes = await fetch(dohUrl);
      const dohData = await dohRes.json();
      
      let foundDelegation = false;
      if (dohData.Answer && dohData.Answer.length > 0) {
        for (const ans of dohData.Answer) {
          // DoH returns TXT records enclosed in quotes
          const recordStr = ans.data.replace(/"/g, '').trim();
          if (recordStr.startsWith('iss=')) {
            const delegatedIssuer = recordStr.substring(4).trim();
            if (delegatedIssuer === tokenIssuer) {
              foundDelegation = true;
              break;
            }
          }
        }
      }
      
      if (foundDelegation) {
        authorizedBy = 'DNS TXT Record Delegation';
        details = `Successfully verified DNS delegation via DoH: TXT record at ${dnsLookupTarget} delegates authority to issuer ${tokenIssuer}`;
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
    
    // Check if we have a hardcoded fallback for this issuer to bypass CORS
    const knownIssuer = WELL_KNOWN_ISSUERS[tokenIssuer];
    
    if (knownIssuer) {
      issuerMetadata = knownIssuer.issuerMetadata;
      idpJwksUri = issuerMetadata.jwks_uri;
      
      if (knownIssuer.issuerJWKS) {
        issuerJWKS = knownIssuer.issuerJWKS;
      } else {
        // Fetch JWKS dynamically since it supports CORS
        const jwksRes = await fetch(idpJwksUri);
        issuerJWKS = await jwksRes.json();
      }
    } else {
      // Attempt dynamic discovery (might fail due to CORS if the IdP hasn't configured CORS on /.well-known)
      try {
        const metadataResponse = await fetch(wellKnownUrl);
        if (!metadataResponse.ok) throw new Error(`Metadata HTTP error ${metadataResponse.status}`);
        issuerMetadata = await metadataResponse.json();
        idpJwksUri = issuerMetadata.jwks_uri;
        
        const jwksResponse = await fetch(idpJwksUri);
        if (!jwksResponse.ok) throw new Error(`JWKS HTTP error ${jwksResponse.status}`);
        issuerJWKS = await jwksResponse.json();
      } catch (fetchErr) {
        throw new Error(`Issuer discovery failed (likely due to CORS restriction on the IdP). Technical error: ${fetchErr.message}`);
      }
    }

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
    const signingAlg = decodeJwtPart(sdJwtString.split('.')[0]).alg || 'EdDSA';

    // Parse the JWKS into a format jose can use
    const jwkStore = jose.createLocalJWKSet(issuerJWKS);
    
    const { payload } = await jose.jwtVerify(sdJwtString, jwkStore, {
      issuer: tokenIssuer,
      algorithms: [signingAlg]
    });

    trace.push({
      step: 5,
      name: 'Issuer Signature Cryptographic Verification',
      status: 'success',
      description: 'Cryptographically verify the EVT signature using the fetched issuer public keys from their JWKS.',
      inputs: {
        evtJwt: sdJwtString,
        signingAlg
      },
      outputs: {
        verifiedPayload: payload,
        cryptographicallyVerified: true
      }
    });
  } catch (error) {
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

    let alg = 'ES256';
    if (ephemeralPublicKey.crv === 'Ed25519' || ephemeralPublicKey.alg === 'EdDSA') {
      alg = 'EdDSA';
    }
    const importedEphemeralKey = await jose.importJWK(ephemeralPublicKey, alg);

    // Verify the KB-JWT using the imported key
    const { payload: kbVerifiedPayload } = await jose.jwtVerify(kbJwtString, importedEphemeralKey, {
      audience: expectedAudience
    });

    trace.push({
      step: 6,
      name: 'Ephemeral Key Binding Cryptographic Verification',
      status: 'success',
      description: 'Extract the browser\'s ephemeral public key from the validated EVT and cryptographically verify the KB-JWT signature to prove possession of the private key.',
      inputs: {
        cnf: sdPayload.cnf,
        kbJwt: kbJwtString
      },
      outputs: {
        extractedBrowserJwk: ephemeralPublicKey,
        kbPayloadHeader: decodeJwtPart(kbJwtString.split('.')[0]),
        kbPayloadBody: kbVerifiedPayload,
        keyBindingPassed: true,
        holderVerification: 'Holder Private Key possession verified.'
      }
    });
  } catch (error) {
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

function escapeHtml(string) {
  return String(string)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
