'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  generateEd25519KeyPairJwk,
  generateP256KeyPairJwk,
  createMockIssuerKeys,
  signCompactJws,
  verifyEvpToken,
  parseSignatureKeyHwk,
  extractSignatureInputParams,
  handleIssuanceRequest,
  simulateBrowserEvpFlow,
} = require('../evp-core');
const { createEvpLocalhostServer } = require('../server');

function createMockFetchForIssuer(issuerOrigin, jwksKeys) {
  return async (url) => {
    if (url === `${issuerOrigin}/.well-known/email-verification`) {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          issuer: issuerOrigin,
          issuance_endpoint: `${issuerOrigin}/email-verification/issuance`,
          jwks_uri: `${issuerOrigin}/.well-known/vc-public-jwks`,
          signing_alg_values_supported: ['EdDSA', 'ES256'],
        }),
      };
    }
    if (url === `${issuerOrigin}/.well-known/vc-public-jwks`) {
      return {
        ok: true,
        status: 200,
        json: async () => ({ keys: jwksKeys }),
      };
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };
}

test('1. End-to-End Happy Path (EdDSA / Ed25519): RFC 9421 Issuance -> KB-JWT -> 6-Step Verifier on localhost', async () => {
  const issuerOrigin = 'http://localhost:3000';
  const verifierOrigin = 'http://localhost:3000';
  const email = 'demo@localhost.example';
  const nonce = 'nonce-12345-uuid';
  const issuerKeyPair = createMockIssuerKeys('EdDSA', 'key-eddsa-1', true);

  const sim = simulateBrowserEvpFlow({
    email,
    nonce,
    verifierOrigin,
    issuerOrigin,
    issuerKeyPair,
    holderAlg: 'EdDSA',
    includeKidInEvt: true,
  });

  const result = await verifyEvpToken({
    rawToken: sim.presentationToken,
    submittedEmail: email,
    expectedNonce: nonce,
    expectedAudience: verifierOrigin,
    localDnsOverrides: { 'localhost.example': issuerOrigin },
    fetchImpl: createMockFetchForIssuer(issuerOrigin, [issuerKeyPair.publicJwk]),
  });

  assert.equal(result.verified, true);
  assert.equal(result.email, email);
  assert.equal(result.issuer, issuerOrigin);
  assert.equal(result.traceSteps.length, 6);
  for (const step of result.traceSteps) {
    assert.equal(step.status, 'success', `${step.name} should succeed`);
  }
});

test('2. End-to-End Happy Path (ES256 / ECDSA P-256): createMockIssuerKeys("ES256") & holderAlg: "ES256"', async () => {
  const issuerOrigin = 'http://localhost:3000';
  const verifierOrigin = 'http://localhost:3000';
  const email = 'es256-user@localhost.example';
  const nonce = 'nonce-es256-uuid';
  const issuerKeyPair = createMockIssuerKeys('ES256', 'key-es256-1', true);

  assert.equal(issuerKeyPair.alg, 'ES256');
  assert.equal(issuerKeyPair.publicJwk.kty, 'EC');
  assert.equal(issuerKeyPair.publicJwk.crv, 'P-256');

  const sim = simulateBrowserEvpFlow({
    email,
    nonce,
    verifierOrigin,
    issuerOrigin,
    issuerKeyPair,
    holderAlg: 'ES256',
    includeKidInEvt: true,
  });

  const result = await verifyEvpToken({
    rawToken: sim.presentationToken,
    submittedEmail: email,
    expectedNonce: nonce,
    expectedAudience: verifierOrigin,
    localDnsOverrides: { 'localhost.example': issuerOrigin },
    fetchImpl: createMockFetchForIssuer(issuerOrigin, [issuerKeyPair.publicJwk]),
  });

  assert.equal(result.verified, true);
  assert.equal(result.email, email);
  assert.equal(result.traceSteps[4].inputSent.signingAlg, 'ES256');
  assert.equal(result.traceSteps[5].inputSent.kbSigningAlg, 'ES256');
  assert.equal(result.traceSteps[5].status, 'success');
});

test('3. JWKS Key Lookup: Verifier loops over JWKS keys when EVT or JWKS omits kid (Gmail style)', async () => {
  const issuerOrigin = 'https://accounts.google.com';
  const verifierOrigin = 'http://localhost:3000';
  const email = 'user@gmail.com';
  const nonce = 'gmail-nonce-999';

  const wrongKey = generateEd25519KeyPairJwk('rotated-old-key', true);
  const actualSigningKey = generateEd25519KeyPairJwk(null, false); // No kid

  // 3a. EVT omits kid, JWKS has multiple keys
  const sim = simulateBrowserEvpFlow({
    email,
    nonce,
    verifierOrigin,
    issuerOrigin,
    issuerKeyPair: actualSigningKey,
    includeKidInEvt: false,
  });

  const result = await verifyEvpToken({
    rawToken: sim.presentationToken,
    submittedEmail: email,
    expectedNonce: nonce,
    expectedAudience: verifierOrigin,
    resolveTxtImpl: async (q) => {
      assert.equal(q, '_email-verification.gmail.com');
      return [['iss=accounts.google.com']];
    },
    fetchImpl: createMockFetchForIssuer(issuerOrigin, [wrongKey.publicJwk, actualSigningKey.publicJwk]),
  });

  assert.equal(result.verified, true);
  assert.equal(result.traceSteps[4].outputReceived.kidWasPresentInEvtHeader, false);
  assert.equal(result.traceSteps[4].status, 'success');

  // 3b. EVT has kid, but JWKS key omits kid
  const keyWithKid = createMockIssuerKeys('EdDSA', 'evt-header-kid-123', true);
  const simWithKid = simulateBrowserEvpFlow({
    email,
    nonce,
    verifierOrigin,
    issuerOrigin,
    issuerKeyPair: keyWithKid,
    includeKidInEvt: true,
  });
  const jwkWithoutKid = { ...keyWithKid.publicJwk };
  delete jwkWithoutKid.kid;

  const resultKidlessJwks = await verifyEvpToken({
    rawToken: simWithKid.presentationToken,
    submittedEmail: email,
    expectedNonce: nonce,
    expectedAudience: verifierOrigin,
    resolveTxtImpl: async () => [['iss=accounts.google.com']],
    fetchImpl: createMockFetchForIssuer(issuerOrigin, [jwkWithoutKid]),
  });
  assert.equal(resultKidlessJwks.verified, true);
  assert.equal(resultKidlessJwks.traceSteps[4].outputReceived.matchedKey, 'matched-key-without-kid');
});

test('4. Email Claim Verification: Exact email case preservation & mismatch detection', async () => {
  const issuerOrigin = 'http://localhost:3000';
  const verifierOrigin = 'http://localhost:3000';
  const submittedMixedCase = 'First.Last@localhost.example';
  const nonce = 'case-nonce-1';
  const issuerKeyPair = generateEd25519KeyPairJwk('key-1', true);

  // Issuer returns exact email casing as submitted even if canonical account is lowercase
  const sim = simulateBrowserEvpFlow({
    email: submittedMixedCase,
    nonce,
    verifierOrigin,
    issuerOrigin,
    issuerKeyPair,
    allowedEmails: ['first.last@localhost.example'],
  });

  const okResult = await verifyEvpToken({
    rawToken: sim.presentationToken,
    submittedEmail: submittedMixedCase,
    expectedNonce: nonce,
    expectedAudience: verifierOrigin,
    localDnsOverrides: { 'localhost.example': issuerOrigin },
    enforceExactEmailMatch: true,
    fetchImpl: createMockFetchForIssuer(issuerOrigin, [issuerKeyPair.publicJwk]),
  });
  assert.equal(okResult.verified, true);
  assert.equal(okResult.email, submittedMixedCase);

  // If form submission has different casing while enforceExactEmailMatch=true, Step 2 rejects
  const mismatchResult = await verifyEvpToken({
    rawToken: sim.presentationToken,
    submittedEmail: 'first.last@localhost.example',
    expectedNonce: nonce,
    expectedAudience: verifierOrigin,
    localDnsOverrides: { 'localhost.example': issuerOrigin },
    enforceExactEmailMatch: true,
    fetchImpl: createMockFetchForIssuer(issuerOrigin, [issuerKeyPair.publicJwk]),
  });
  assert.equal(mismatchResult.verified, false);
  assert.equal(mismatchResult.traceSteps[1].status, 'failed');
  assert.match(mismatchResult.error, /Email mismatch/);
});

test('5. Sec-Fetch-Dest Validation: Accepts email-verification & emailverification, rejects invalid', () => {
  const issuerKeyPair = generateEd25519KeyPairJwk('key-1', true);
  const sim = simulateBrowserEvpFlow({
    email: 'demo@localhost.example',
    nonce: 'n1',
    verifierOrigin: 'http://localhost:3000',
    issuerOrigin: 'http://localhost:3000',
    issuerKeyPair,
  });

  // Chrome 154+ `email-verification`
  const res154 = handleIssuanceRequest({
    method: 'POST',
    authority: 'localhost:3000',
    path: '/email-verification/issuance',
    headers: { ...sim.issuanceRequestHeaders, 'Sec-Fetch-Dest': 'email-verification' },
    rawBody: sim.issuanceRequestBody,
    isSessionLoggedIn: true,
    allowedEmails: ['demo@localhost.example'],
    issuerOrigin: 'http://localhost:3000',
    issuerKeyPair,
  });
  assert.equal(res154.status, 200);

  // Chrome 153 `emailverification`
  const res153 = handleIssuanceRequest({
    method: 'POST',
    authority: 'localhost:3000',
    path: '/email-verification/issuance',
    headers: { ...sim.issuanceRequestHeaders, 'Sec-Fetch-Dest': 'emailverification' },
    rawBody: sim.issuanceRequestBody,
    isSessionLoggedIn: true,
    allowedEmails: ['demo@localhost.example'],
    issuerOrigin: 'http://localhost:3000',
    issuerKeyPair,
  });
  assert.equal(res153.status, 200);

  // Invalid `Sec-Fetch-Dest: document` (CSRF protection)
  const resBad = handleIssuanceRequest({
    method: 'POST',
    authority: 'localhost:3000',
    path: '/email-verification/issuance',
    headers: { ...sim.issuanceRequestHeaders, 'Sec-Fetch-Dest': 'document' },
    rawBody: sim.issuanceRequestBody,
    isSessionLoggedIn: true,
    allowedEmails: ['demo@localhost.example'],
    issuerOrigin: 'http://localhost:3000',
    issuerKeyPair,
  });
  assert.equal(resBad.status, 400);
  assert.equal(resBad.body.error, 'invalid_request');
});

test('6. Security & Edge Cases: Tampered Content-Digest, Nonce Replay, Wrong Audience, Expired Token, Non-HTTPS DNS Delegation', async () => {
  const issuerOrigin = 'http://localhost:3000';
  const verifierOrigin = 'http://localhost:3000';
  const email = 'demo@localhost.example';
  const nonce = 'sec-nonce-1';
  const issuerKeyPair = generateEd25519KeyPairJwk('key-1', true);

  const sim = simulateBrowserEvpFlow({
    email,
    nonce,
    verifierOrigin,
    issuerOrigin,
    issuerKeyPair,
    nowSeconds: 1780000000,
  });

  // 6a. Tampered body in RFC 9421 issuance request fails Content-Digest check
  const tamperedIssuance = handleIssuanceRequest({
    method: 'POST',
    authority: 'localhost:3000',
    path: '/email-verification/issuance',
    headers: sim.issuanceRequestHeaders,
    rawBody: JSON.stringify({ email: 'attacker@localhost.example' }),
    isSessionLoggedIn: true,
    allowedEmails: ['demo@localhost.example', 'attacker@localhost.example'],
    issuerOrigin,
    issuerKeyPair,
  });
  assert.equal(tamperedIssuance.status, 400);
  assert.equal(tamperedIssuance.body.error, 'invalid_signature');

  // 6b. Missing session nonce (replay attack) fails Step 2
  const missingNonceRes = await verifyEvpToken({
    rawToken: sim.presentationToken,
    submittedEmail: email,
    expectedNonce: '',
    expectedAudience: verifierOrigin,
    localDnsOverrides: { 'localhost.example': issuerOrigin },
    fetchImpl: createMockFetchForIssuer(issuerOrigin, [issuerKeyPair.publicJwk]),
    nowSeconds: 1780000010,
  });
  assert.equal(missingNonceRes.verified, false);
  assert.equal(missingNonceRes.traceSteps[1].status, 'failed');

  // 6c. Wrong audience fails Step 6
  const wrongAudRes = await verifyEvpToken({
    rawToken: sim.presentationToken,
    submittedEmail: email,
    expectedNonce: nonce,
    expectedAudience: 'https://phishing.example',
    localDnsOverrides: { 'localhost.example': issuerOrigin },
    fetchImpl: createMockFetchForIssuer(issuerOrigin, [issuerKeyPair.publicJwk]),
    nowSeconds: 1780000010,
  });
  assert.equal(wrongAudRes.verified, false);
  assert.equal(wrongAudRes.traceSteps[5].status, 'failed');
  assert.match(wrongAudRes.error, /audience mismatch/);

  // 6d. Expired token fails Step 5
  const expiredRes = await verifyEvpToken({
    rawToken: sim.presentationToken,
    submittedEmail: email,
    expectedNonce: nonce,
    expectedAudience: verifierOrigin,
    localDnsOverrides: { 'localhost.example': issuerOrigin },
    fetchImpl: createMockFetchForIssuer(issuerOrigin, [issuerKeyPair.publicJwk]),
    nowSeconds: 1780001000, // +1000s > 300s exp + 60s skew
  });
  assert.equal(expiredRes.verified, false);
  assert.equal(expiredRes.traceSteps[4].status, 'failed');
  assert.match(expiredRes.error, /expired/);

  // 6e. Step 3 DNS Delegation rejects plain http:// scheme for non-localhost issuers
  const evilHttpIssuer = 'http://evil-non-local.example';
  const simEvil = simulateBrowserEvpFlow({
    email: 'victim@evil-non-local.example',
    nonce,
    verifierOrigin,
    issuerOrigin: evilHttpIssuer,
    issuerKeyPair,
  });
  const badSchemeRes = await verifyEvpToken({
    rawToken: simEvil.presentationToken,
    submittedEmail: 'victim@evil-non-local.example',
    expectedNonce: nonce,
    expectedAudience: verifierOrigin,
    resolveTxtImpl: async () => [[`iss=${evilHttpIssuer}`]],
    fetchImpl: createMockFetchForIssuer(evilHttpIssuer, [issuerKeyPair.publicJwk]),
  });
  assert.equal(badSchemeRes.verified, false);
  assert.equal(badSchemeRes.traceSteps[2].status, 'failed');
  assert.match(badSchemeRes.error, /must use 'https:\/\/' scheme/);
});

test('7. Dynamic RFC 9421 @signature-params order handling & extra structured parameters succeed', async () => {
  const issuerOrigin = 'http://localhost:3000';
  const verifierOrigin = 'http://localhost:3000';
  const email = 'demo@localhost.example';
  const nonce = 'custom-order-nonce';
  const issuerKeyPair = createMockIssuerKeys('EdDSA');

  const sim = simulateBrowserEvpFlow({
    email,
    nonce,
    verifierOrigin,
    issuerOrigin,
    issuerKeyPair,
    customComponentOrder: ['signature-key', 'sec-fetch-dest', 'content-digest', '@target-uri', '@method'],
  });

  assert.match(
    sim.issuanceRequestHeaders['Signature-Input'],
    /^sig=\("signature-key" "sec-fetch-dest" "content-digest" "@target-uri" "@method"\);created=/
  );

  // Also verify multi-signature & extra RFC 9421 parameters parsing (;alg="ed25519";keyid="holder-1")
  const parsedMulti = extractSignatureInputParams(
    'other=("@method");created=123, sig=("@method" "@authority" "@path" "content-digest" "signature-key");created=1780000000;alg="ed25519";keyid="holder-1"'
  );
  assert.equal(parsedMulti.created, 1780000000);
  assert.deepEqual(parsedMulti.components, ['@method', '@authority', '@path', 'content-digest', 'signature-key']);

  const result = await verifyEvpToken({
    rawToken: sim.presentationToken,
    submittedEmail: email,
    expectedNonce: nonce,
    expectedAudience: verifierOrigin,
    localDnsOverrides: { 'localhost.example': issuerOrigin },
    fetchImpl: createMockFetchForIssuer(issuerOrigin, [issuerKeyPair.publicJwk]),
  });

  assert.equal(result.verified, true);
});

test('8. Missing required RFC 9421 component or created parameter in Signature-Input is rejected', () => {
  const issuerKeyPair = createMockIssuerKeys('EdDSA');
  const sim = simulateBrowserEvpFlow({
    email: 'demo@localhost.example',
    nonce: 'n8',
    verifierOrigin: 'http://localhost:3000',
    issuerOrigin: 'http://localhost:3000',
    issuerKeyPair,
  });

  // 8a. Missing `content-digest` in Signature-Input component list
  const resMissingComp = handleIssuanceRequest({
    method: 'POST',
    authority: 'localhost:3000',
    path: '/email-verification/issuance',
    headers: {
      ...sim.issuanceRequestHeaders,
      'Signature-Input': 'sig=("@method" "@authority" "@path" "signature-key");created=1780000000',
    },
    rawBody: sim.issuanceRequestBody,
    isSessionLoggedIn: true,
    allowedEmails: ['demo@localhost.example'],
    issuerOrigin: 'http://localhost:3000',
    issuerKeyPair,
  });
  assert.equal(resMissingComp.status, 400);
  assert.equal(resMissingComp.body.error, 'invalid_signature');
  assert.match(resMissingComp.body.error_description, /missing required EVP covered components/i);

  // 8b. Missing `;created=` parameter in Signature-Input
  const resMissingCreated = handleIssuanceRequest({
    method: 'POST',
    authority: 'localhost:3000',
    path: '/email-verification/issuance',
    headers: {
      ...sim.issuanceRequestHeaders,
      'Signature-Input': 'sig=("@method" "@authority" "@path" "content-digest" "signature-key")',
    },
    rawBody: sim.issuanceRequestBody,
    isSessionLoggedIn: true,
    allowedEmails: ['demo@localhost.example'],
    issuerOrigin: 'http://localhost:3000',
    issuerKeyPair,
  });
  assert.equal(resMissingCreated.status, 400);
  assert.equal(resMissingCreated.body.error, 'invalid_signature');
  assert.match(resMissingCreated.body.error_description, /created/i);
});

test('9. Unquoted RFC 8941 Signature-Key parameters (kty=OKP;crv=Ed25519 and kty=EC;crv=P-256) are supported', async () => {
  const issuerOrigin = 'http://localhost:3000';
  const verifierOrigin = 'http://localhost:3000';
  const email = 'demo@localhost.example';
  const nonce = 'unquoted-sig-key-nonce';
  const issuerKeyPair = createMockIssuerKeys('ES256');

  const sim = simulateBrowserEvpFlow({
    email,
    nonce,
    verifierOrigin,
    issuerOrigin,
    issuerKeyPair,
    holderAlg: 'ES256',
    unquotedSignatureKey: true,
  });

  // Verify the generated Signature-Key header uses unquoted RFC 8941 token syntax
  assert.match(sim.issuanceRequestHeaders['Signature-Key'], /^sig=hwk;crv=P-256;kty=EC;x=[^"]+;y=[^"]+$/);

  const result = await verifyEvpToken({
    rawToken: sim.presentationToken,
    submittedEmail: email,
    expectedNonce: nonce,
    expectedAudience: verifierOrigin,
    localDnsOverrides: { 'localhost.example': issuerOrigin },
    fetchImpl: createMockFetchForIssuer(issuerOrigin, [issuerKeyPair.publicJwk]),
  });

  assert.equal(result.verified, true);
});

test('10. Incomplete EC (P-256) Signature-Key hwk missing y coordinate or unsupported alg is rejected', () => {
  assert.throws(
    () => parseSignatureKeyHwk('sig=hwk;crv="P-256";kty="EC";x="dGVzdC14LWNvb3JkaW5hdGU"'),
    /requires crv='P-256' and both 'x' and 'y' coordinates/
  );

  // Unsupported algorithm returns Signature-Error: error=unsupported_algorithm
  const issuerKeyPair = createMockIssuerKeys('EdDSA', 'key-1', true);
  const sim = simulateBrowserEvpFlow({
    email: 'demo@localhost.example',
    nonce: 'alg-err-nonce',
    verifierOrigin: 'http://localhost:3000',
    issuerOrigin: 'http://localhost:3000',
    issuerKeyPair,
  });
  const res = handleIssuanceRequest({
    method: 'POST',
    authority: 'localhost:3000',
    path: '/email-verification/issuance',
    headers: {
      ...sim.issuanceRequestHeaders,
      'Signature-Key': `${sim.issuanceRequestHeaders['Signature-Key']};alg="RS256"`,
    },
    rawBody: sim.issuanceRequestBody,
    isSessionLoggedIn: true,
    allowedEmails: ['demo@localhost.example'],
    issuerOrigin: 'http://localhost:3000',
    issuerKeyPair,
  });
  assert.equal(res.status, 400);
  assert.equal(res.headers['Signature-Error'], 'error=unsupported_algorithm');
});

test('11. Security Rejection: cnf.jwk exposing private key material ("d") is rejected in Step 6', async () => {
  const issuerOrigin = 'http://localhost:3000';
  const verifierOrigin = 'http://localhost:3000';
  const email = 'demo@localhost.example';
  const nonce = 'private-key-leak-nonce';
  const issuerKeyPair = createMockIssuerKeys('EdDSA', 'key-1', true);
  const holder = generateEd25519KeyPairJwk(null, false);
  const nowSeconds = Math.floor(Date.now() / 1000);

  // Maliciously or accidentally include holder.privateJwk (with 'd') in EVT cnf.jwk
  const evtHeader = { alg: 'EdDSA', typ: 'evt+jwt', kid: 'key-1' };
  const evtPayload = {
    iss: issuerOrigin,
    iat: nowSeconds,
    exp: nowSeconds + 300,
    cnf: {
      jwk: holder.privateJwk, // Contains private key field `d`!
    },
    email,
    email_verified: true,
  };
  const evtJwt = signCompactJws(evtHeader, evtPayload, issuerKeyPair.privateKey);
  const issuanceToken = `${evtJwt}~`;
  const sdHash = crypto.createHash('sha256').update(issuanceToken, 'ascii').digest('base64url');
  const kbJwt = signCompactJws(
    { alg: 'EdDSA', typ: 'kb+jwt' },
    { aud: verifierOrigin, nonce, iat: nowSeconds, sd_hash: sdHash },
    holder.privateKey
  );

  const res = await verifyEvpToken({
    rawToken: `${issuanceToken}${kbJwt}`,
    submittedEmail: email,
    expectedNonce: nonce,
    expectedAudience: verifierOrigin,
    localDnsOverrides: { 'localhost.example': issuerOrigin },
    fetchImpl: createMockFetchForIssuer(issuerOrigin, [issuerKeyPair.publicJwk]),
    nowSeconds,
  });

  assert.equal(res.verified, false);
  assert.equal(res.traceSteps[5].status, 'failed');
  assert.match(res.error, /private key material \('d'\)/);
});

test('12. Security Rejection: Future-dated iat timestamp beyond clock skew tolerance (>60s) is rejected', async () => {
  const issuerOrigin = 'http://localhost:3000';
  const verifierOrigin = 'http://localhost:3000';
  const email = 'demo@localhost.example';
  const nonce = 'future-iat-nonce';
  const issuerKeyPair = createMockIssuerKeys('EdDSA', 'key-1', true);
  const nowSeconds = 1780000000;

  // Issue token 120 seconds in the future (> 60s clock skew limit)
  const sim = simulateBrowserEvpFlow({
    email,
    nonce,
    verifierOrigin,
    issuerOrigin,
    issuerKeyPair,
    nowSeconds: nowSeconds + 120,
  });

  const res = await verifyEvpToken({
    rawToken: sim.presentationToken,
    submittedEmail: email,
    expectedNonce: nonce,
    expectedAudience: verifierOrigin,
    localDnsOverrides: { 'localhost.example': issuerOrigin },
    fetchImpl: createMockFetchForIssuer(issuerOrigin, [issuerKeyPair.publicJwk]),
    nowSeconds,
  });

  assert.equal(res.verified, false);
  assert.equal(res.traceSteps[4].status, 'failed');
  assert.match(res.error, /future issuance timestamp/);
});

test('13. Live HTTP Server Integration Test on ephemeral localhost port (including /mock-provider/toggle-alg ES256 switch)', async () => {
  const { server } = createEvpLocalhostServer({ includeKidInEvt: false }); // Test Gmail-style kid-less mode live!
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const baseUrl = `http://localhost:${port}`;

  try {
    // 1. Toggle Mock Issuer key algorithm from EdDSA to ES256 via POST /mock-provider/toggle-alg
    const toggleRes = await fetch(`${baseUrl}/mock-provider/toggle-alg`, {
      method: 'POST',
      redirect: 'manual',
    });
    assert.equal(toggleRes.status, 303);

    // 2. GET / to obtain SSR form and single-use session nonce cookie
    const getRes = await fetch(`${baseUrl}/`);
    assert.equal(getRes.status, 200);
    const setCookie = getRes.headers.get('set-cookie') || '';
    const nonceMatch = setCookie.match(/evp_rp_nonce=([^;]+)/);
    assert.ok(nonceMatch, 'Should set evp_rp_nonce cookie');
    const nonce = decodeURIComponent(nonceMatch[1]);
    const html = await getRes.text();
    assert.ok(html.includes(`nonce="${nonce}"`), 'SSR HTML should embed nonce in hidden input');
    assert.ok(html.includes('ES256 (ECDSA P-256)'), 'SSR HTML should reflect toggled ES256 issuer algorithm');

    // 3. POST /api/simulate-browser-issuance
    const simRes = await fetch(`${baseUrl}/api/simulate-browser-issuance`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'demo@localhost.example', nonce }),
    });
    assert.equal(simRes.status, 200);
    const { presentationToken, presentation_token } = await simRes.json();
    assert.ok(presentationToken.includes('~'));
    assert.equal(presentationToken, presentation_token);

    // 4. POST / with form data and Cookie header
    const postRes = await fetch(`${baseUrl}/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: `evp_rp_nonce=${encodeURIComponent(nonce)}`,
      },
      body: new URLSearchParams({
        email: 'demo@localhost.example',
        token: presentationToken,
      }).toString(),
    });
    assert.equal(postRes.status, 200);
    const postHtml = await postRes.text();
    assert.ok(postHtml.includes('Email successfully verified via EVP!'), 'Should render verification success banner');

    // 5. Direct HTTP POST /email-verification/issuance with mixed-case custom email (`First.Last@localhost.example`)
    const simMixed = simulateBrowserEvpFlow({
      email: 'First.Last@localhost.example',
      nonce: 'direct-issuance-nonce',
      verifierOrigin: baseUrl,
      issuerOrigin: baseUrl,
    });
    const directIssuanceRes = await fetch(`${baseUrl}/email-verification/issuance`, {
      method: 'POST',
      headers: simMixed.issuanceRequestHeaders,
      body: simMixed.issuanceRequestBody,
    });
    assert.equal(directIssuanceRes.status, 200, 'POST /email-verification/issuance should accept any @localhost.example email when signed in');
    const directIssuanceData = await directIssuanceRes.json();
    assert.ok(directIssuanceData.issuance_token.endsWith('~'));
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('14. Chrome 154–156 default RFC 9421 Signature-Input ("@method" "@target-uri" "content-digest" "sec-fetch-dest" "signature-key") & Chrome 153 backward compatibility ("@method" "@authority" "@path" "content-digest" "signature-key")', async () => {
  const issuerOrigin = 'http://localhost:3000';
  const verifierOrigin = 'http://localhost:3000';
  const email = 'demo@localhost.example';
  const nonce = 'chrome-156-default-components-nonce';
  const issuerKeyPair = createMockIssuerKeys('EdDSA', 'key-156', true);

  // 14a. Default simulateBrowserEvpFlow uses Chrome 154–156's covered components
  const sim156 = simulateBrowserEvpFlow({
    email,
    nonce,
    verifierOrigin,
    issuerOrigin,
    issuerKeyPair,
  });

  assert.match(
    sim156.issuanceRequestHeaders['Signature-Input'],
    /^sig=\("@method" "@target-uri" "content-digest" "sec-fetch-dest" "signature-key"\);created=\d+$/
  );

  // 14b. Backward-compatible Chrome 153 component list ("@method" "@authority" "@path" "content-digest" "signature-key")
  const sim153 = simulateBrowserEvpFlow({
    email,
    nonce,
    verifierOrigin,
    issuerOrigin,
    issuerKeyPair,
    componentOrder: ['@method', '@authority', '@path', 'content-digest', 'signature-key'],
    secFetchDest: 'emailverification',
  });

  assert.match(
    sim153.issuanceRequestHeaders['Signature-Input'],
    /^sig=\("@method" "@authority" "@path" "content-digest" "signature-key"\);created=\d+$/
  );

  const verified153 = await verifyEvpToken({
    rawToken: sim153.presentationToken,
    submittedEmail: email,
    expectedNonce: nonce,
    expectedAudience: verifierOrigin,
    localDnsOverrides: { 'localhost.example': issuerOrigin },
    fetchImpl: createMockFetchForIssuer(issuerOrigin, [issuerKeyPair.publicJwk]),
  });
  assert.equal(verified153.verified, true);
});

test('15. Chrome 156 rowan.fyi Failure Diagnosis (Signature-Input @target-uri vs. hardcoded @authority/@path) & Localhost No-Origin-Trial UI Check', async () => {
  const issuerOrigin = 'https://rowan.fyi';
  const verifierOrigin = 'https://rowan.fyi';
  const email = 'demo@rowan.fyi';
  const nonce = 'rowan-fyi-chrome156-nonce';
  const issuerKeyPair = createMockIssuerKeys('EdDSA', 'rowan-fyi-key-1', true);

  // Simulate Chrome 154–156's exact issuance request to rowan.fyi
  const simChrome156 = simulateBrowserEvpFlow({
    email,
    nonce,
    verifierOrigin,
    issuerOrigin,
    issuerKeyPair,
    allowedEmails: ['demo@rowan.fyi'],
  });

  const sigInput = simChrome156.issuanceRequestHeaders['Signature-Input'];
  assert.ok(sigInput.includes('"@target-uri"'), 'Chrome 154–156 sends @target-uri in Signature-Input');
  assert.ok(sigInput.includes('"sec-fetch-dest"'), 'Chrome 154–156 sends sec-fetch-dest in Signature-Input');

  // Reproduce rowan-fyi/src/pages/made/email-provider/issuance.ts lines 113–118:
  const rowanFyiRequiredComponents = ['@method', '@authority', '@path', 'content-digest', 'signature-key'];
  const missingInRowanFyi = rowanFyiRequiredComponents.filter((comp) => !sigInput.includes(`"${comp}"`));
  assert.deepEqual(
    missingInRowanFyi,
    ['@authority', '@path'],
    'rowan-fyi issuance.ts rejects Chrome 154–156 Signature-Input because @authority and @path are replaced by @target-uri'
  );

  // Confirm our handleIssuanceRequest and verifyEvpToken succeed on the exact same Chrome 154–156 request
  const ourIssuanceRes = handleIssuanceRequest({
    method: 'POST',
    authority: 'rowan.fyi',
    path: '/email-verification/issuance',
    headers: simChrome156.issuanceRequestHeaders,
    rawBody: simChrome156.issuanceRequestBody,
    isSessionLoggedIn: true,
    allowedEmails: ['demo@rowan.fyi'],
    issuerOrigin,
    issuerKeyPair,
  });
  assert.equal(ourIssuanceRes.status, 200);
  assert.ok(ourIssuanceRes.body.issuance_token.endsWith('~'));
});

test('16. Static GitHub Pages SPA Assets (/index.html, /app.js, /style.css, /traditional.html, /explainer.html, /glossary.html) & Chrome 153–156 Client-Side Support', async () => {
  const { server } = createEvpLocalhostServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const indexRes = await fetch(`${baseUrl}/index.html`);
    assert.equal(indexRes.status, 200);
    const indexHtml = await indexRes.text();
    assert.match(indexHtml, /simulate-evp-btn/);
    assert.match(indexHtml, /EmailVerifiedEvent/);

    const appJsRes = await fetch(`${baseUrl}/app.js`);
    assert.equal(appJsRes.status, 200);
    const appJs = await appJsRes.text();
    assert.match(appJs, /addEventListener\('emailverified'/);
    assert.match(appJs, /EmailVerifiedEvent/);
    assert.match(appJs, /"@target-uri"/);
    assert.match(appJs, /Sec-Fetch-Dest: email-verification/);
    assert.match(appJs, /ES256/);
    assert.match(appJs, /EdDSA/);
    assert.match(appJs, /Gmail compatibility mode/);

    assert.match(appJs, /submittedEmail\.trim\(\) !== tokenEmail\.trim\(\)/);
    assert.match(appJs, /kbJwtDecodedHeader\.alg/);
    assert.match(appJs, /initChallenge\(\)/);

    const explainerRes = await fetch(`${baseUrl}/explainer.html`);
    assert.equal(explainerRes.status, 200);
    const explainerHtml = await explainerRes.text();
    assert.ok(!explainerHtml.includes('RSA'), 'explainer.html must not advertise RSA keys');
    assert.match(explainerHtml, /Ed25519/);
    assert.match(explainerHtml, /P-256/);
    assert.match(explainerHtml, /iss=https:\/\/accounts\.demo-mail\.com/);

    const glossaryRes = await fetch(`${baseUrl}/glossary.html`);
    assert.equal(glossaryRes.status, 200);
    const glossaryHtml = await glossaryRes.text();
    assert.match(glossaryHtml, /RFC 9421/);
    assert.match(glossaryHtml, /EdDSA &amp; ES256/);
    assert.match(glossaryHtml, /EmailVerifiedEvent/);

    for (const p of ['/style.css', '/traditional.html']) {
      const res = await fetch(`${baseUrl}${p}`);
      assert.equal(res.status, 200, `Expected 200 for ${p}`);
    }
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('17. JWKS Key Rotation Fallback: EVT with rotated/mismatched kid succeeds by falling back to remaining JWKS keys', async () => {
  const issuerOrigin = 'https://issuer.example.com';
  const verifierOrigin = 'http://localhost:3000';
  const email = 'Alice.Rotation@localhost.example';
  const nonce = 'nonce-key-rotation-17';

  // EVT is signed with a key whose header has `kid: "old-kid-v1"`, while JWKS has `kid: "distractor-v0"` and `kid: "new-kid-v2"` (same key material under rotated kid)
  const distractorKeyPair = createMockIssuerKeys('EdDSA', 'distractor-v0', true);
  const signingKeyPair = createMockIssuerKeys('EdDSA', 'old-kid-v1', true);
  const rotatedPublicJwk = { ...signingKeyPair.publicJwk, kid: 'new-kid-v2' };

  const sim = simulateBrowserEvpFlow({
    email,
    nonce,
    verifierOrigin,
    issuerOrigin,
    issuerKeyPair: signingKeyPair,
    includeKidInEvt: true,
  });

  const result = await verifyEvpToken({
    rawToken: sim.presentationToken,
    submittedEmail: email,
    expectedNonce: nonce,
    expectedAudience: verifierOrigin,
    localDnsOverrides: { 'localhost.example': issuerOrigin },
    fetchImpl: createMockFetchForIssuer(issuerOrigin, [distractorKeyPair.publicJwk, rotatedPublicJwk]),
  });

  assert.equal(result.verified, true);
  assert.equal(result.email, 'Alice.Rotation@localhost.example');
  assert.equal(result.traceSteps[4].outputReceived.matchedKey, 'new-kid-v2');
});


