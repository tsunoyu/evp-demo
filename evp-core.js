'use strict';

const crypto = require('node:crypto');
const dns = require('node:dns/promises');

/**
 * Base64url helpers
 */
function toBase64Url(bufOrStr) {
  const buf = Buffer.isBuffer(bufOrStr) ? bufOrStr : Buffer.from(bufOrStr, 'utf8');
  return buf.toString('base64url');
}

function fromBase64UrlToString(b64u) {
  return Buffer.from(b64u, 'base64url').toString('utf8');
}

/**
 * Generates an Ed25519 keypair and exports public/private JWKs for the Mock Issuer or Ephemeral Browser Holder.
 */
function generateEd25519KeyPairJwk(kid = 'local-issuer-key-1', includeKid = true) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicJwk = publicKey.export({ format: 'jwk' });
  const privateJwk = privateKey.export({ format: 'jwk' });

  publicJwk.alg = 'EdDSA';
  publicJwk.use = 'sig';
  privateJwk.alg = 'EdDSA';

  if (includeKid && kid) {
    publicJwk.kid = kid;
    privateJwk.kid = kid;
  }

  return { publicKey, privateKey, publicJwk, privateJwk, alg: 'EdDSA' };
}

/**
 * Generates an ECDSA P-256 (ES256) keypair and exports public/private JWKs.
 */
function generateP256KeyPairJwk(kid = 'local-issuer-p256-1', includeKid = true) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });
  const publicJwk = publicKey.export({ format: 'jwk' });
  const privateJwk = privateKey.export({ format: 'jwk' });

  publicJwk.alg = 'ES256';
  publicJwk.use = 'sig';
  privateJwk.alg = 'ES256';

  if (includeKid && kid) {
    publicJwk.kid = kid;
    privateJwk.kid = kid;
  }

  return { publicKey, privateKey, publicJwk, privateJwk, alg: 'ES256' };
}

/**
 * Creates Mock Issuer keys supporting either 'EdDSA' (Ed25519) or 'ES256' (ECDSA P-256).
 */
function createMockIssuerKeys(alg = 'EdDSA', kid = undefined, includeKid = true) {
  if (alg === 'ES256') {
    return generateP256KeyPairJwk(kid === undefined ? 'local-issuer-es256-1' : kid, includeKid);
  }
  if (alg === 'EdDSA' || alg === 'Ed25519') {
    return generateEd25519KeyPairJwk(kid === undefined ? 'local-issuer-eddsa-1' : kid, includeKid);
  }
  throw new Error(`Unsupported mock issuer key algorithm: ${alg}. Expected 'EdDSA' or 'ES256'.`);
}

/**
 * Signs a compact JWS (EdDSA / Ed25519 or ES256) using Node's built-in crypto module.
 */
function signCompactJws(header, payload, privateKeyOrJwk) {
  const privKey =
    privateKeyOrJwk instanceof crypto.KeyObject
      ? privateKeyOrJwk
      : crypto.createPrivateKey({ key: privateKeyOrJwk, format: 'jwk' });

  const headerB64 = toBase64Url(JSON.stringify(header));
  const payloadB64 = toBase64Url(JSON.stringify(payload));
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, 'utf8');

  let signatureBuf;
  if (header.alg === 'ES256') {
    signatureBuf = crypto.sign('sha256', signingInput, {
      key: privKey,
      dsaEncoding: 'ieee-p1363',
    });
  } else {
    // EdDSA / Ed25519
    signatureBuf = crypto.sign(null, signingInput, privKey);
  }

  return `${headerB64}.${payloadB64}.${toBase64Url(signatureBuf)}`;
}

/**
 * Verifies a compact JWS signature against a public JWK (supports EdDSA/Ed25519 and ES256).
 */
function verifyCompactJws(compactJwt, publicJwk, expectedAlg) {
  if (publicJwk && (publicJwk.d || publicJwk.p || publicJwk.q)) {
    throw new Error("Security Exception: Public JWK must not contain private key material ('d').");
  }
  const parts = compactJwt.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid compact JWS format (expected 3 dot-separated parts).');
  }
  const [headerB64, payloadB64, sigB64] = parts;
  const header = JSON.parse(fromBase64UrlToString(headerB64));
  const alg = expectedAlg || header.alg || publicJwk.alg || (publicJwk.kty === 'EC' ? 'ES256' : 'EdDSA');

  const cleanJwk = {
    kty: publicJwk.kty,
    crv: publicJwk.crv,
    x: publicJwk.x,
  };
  if (publicJwk.y) cleanJwk.y = publicJwk.y;

  const pubKey = crypto.createPublicKey({ key: cleanJwk, format: 'jwk' });
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, 'utf8');
  const sigBuf = Buffer.from(sigB64, 'base64url');

  let valid = false;
  if (alg === 'ES256') {
    valid = crypto.verify(
      'sha256',
      signingInput,
      { key: pubKey, dsaEncoding: 'ieee-p1363' },
      sigBuf
    );
  } else if (alg === 'EdDSA' || alg === 'Ed25519') {
    valid = crypto.verify(null, signingInput, pubKey, sigBuf);
  } else {
    throw new Error(`Unsupported JWS algorithm: ${alg}`);
  }

  if (!valid) {
    throw new Error('Cryptographic signature verification failed.');
  }

  return {
    header,
    payload: JSON.parse(fromBase64UrlToString(payloadB64)),
  };
}

/**
 * Decodes an SD-JWT+KB token (`<EVT>~<Disclosure 1>~...~<Disclosure N>~<KB-JWT>`)
 * following RFC 9901.
 */
function decodeSdJwtPresentation(rawToken) {
  if (typeof rawToken !== 'string' || !rawToken.includes('~')) {
    throw new Error('Invalid SD-JWT format: missing tilde (~) delimiter.');
  }

  const lastTildeIndex = rawToken.lastIndexOf('~');
  const sdHashInput = rawToken.substring(0, lastTildeIndex + 1); // Includes trailing '~'
  const rawKbJwt = rawToken.substring(lastTildeIndex + 1);

  if (!rawKbJwt) {
    throw new Error('Missing Key Binding JWT (KB-JWT) after final tilde (~).');
  }

  const sdParts = rawToken.substring(0, lastTildeIndex).split('~');
  const rawEvtJwt = sdParts[0];
  const rawDisclosures = sdParts.slice(1).filter(Boolean);

  const decodeJwtPart = (jwtStr, label) => {
    const pieces = jwtStr.split('.');
    if (pieces.length !== 3) {
      throw new Error(`Malformed ${label}: expected 3 JWT segments, got ${pieces.length}.`);
    }
    try {
      return {
        raw: jwtStr,
        header: JSON.parse(fromBase64UrlToString(pieces[0])),
        payload: JSON.parse(fromBase64UrlToString(pieces[1])),
        signature: pieces[2],
      };
    } catch (err) {
      throw new Error(`Failed to decode ${label} JSON: ${err.message}`);
    }
  };

  const evt = decodeJwtPart(rawEvtJwt, 'EVT');
  const kbJwt = decodeJwtPart(rawKbJwt, 'KB-JWT');

  const disclosures = rawDisclosures.map((rawDisc) => {
    const digest = crypto.createHash('sha256').update(rawDisc, 'ascii').digest('base64url');
    const decodedArray = JSON.parse(fromBase64UrlToString(rawDisc));
    return {
      raw: rawDisc,
      digest,
      salt: decodedArray[0],
      claimName: decodedArray[1],
      claimValue: decodedArray[2],
    };
  });

  // Resolve selectively disclosed claims (if any) into resolvedPayload
  const resolvedPayload = { ...evt.payload };
  if (Array.isArray(evt.payload._sd)) {
    for (const disc of disclosures) {
      if (evt.payload._sd.includes(disc.digest)) {
        resolvedPayload[disc.claimName] = disc.claimValue;
      }
    }
  }

  return {
    rawToken,
    sdHashInput,
    evt,
    kbJwt,
    disclosures,
    resolvedPayload,
  };
}

/**
 * Validates standard JWT time claims (`iat` and `exp`) with clock skew tolerance.
 */
function validateTimeClaims(payload, maxAgeSeconds = 300, clockSkewSeconds = 60, nowSeconds = Math.floor(Date.now() / 1000)) {
  const exp = typeof payload.exp === 'number' ? payload.exp : undefined;
  const iat = typeof payload.iat === 'number' ? payload.iat : undefined;

  if (exp !== undefined && nowSeconds > exp + clockSkewSeconds) {
    throw new Error(`The token has expired (exp: ${exp}, current: ${nowSeconds}).`);
  }
  if (iat === undefined) {
    throw new Error("Required issued-at ('iat') claim is missing.");
  }
  if (exp !== undefined && iat >= exp) {
    throw new Error(`Token timestamps are inconsistent (iat: ${iat} >= exp: ${exp}).`);
  }
  const age = nowSeconds - iat;
  if (age > maxAgeSeconds + clockSkewSeconds) {
    throw new Error(`Token is too old (issued ${age} seconds ago, max limit: ${maxAgeSeconds}s).`);
  }
  if (age < -clockSkewSeconds) {
    throw new Error(`Token has a future issuance timestamp (iat: ${iat}, current: ${nowSeconds}).`);
  }
}

/**
 * Checks whether an issuer discovery/JWKS URL is safe to fetch.
 * Explicitly allows `http://localhost` and `http://127.*` for local development,
 * while enforcing `https:` for all non-local origins (matching rowan.fyi reference).
 */
function isLocalDevHost(hostname) {
  return (
    hostname === 'localhost' ||
    hostname.startsWith('127.') ||
    hostname.endsWith('.c.googlers.com')
  );
}

function isSafeIssuerUrl(urlStr) {
  try {
    const parsed = new URL(urlStr);
    const isLocalDev = isLocalDevHost(parsed.hostname);
    if (parsed.protocol !== 'https:' && !(isLocalDev && parsed.protocol === 'http:')) {
      return false;
    }
    if (!isLocalDev && (parsed.hostname.endsWith('.internal') || parsed.hostname.endsWith('.local'))) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Creates the initial 6-step verification trace matching rowan.fyi/made/email-verification.
 */
function createInitialTraceSteps() {
  return [
    {
      name: 'Step 1: Parse the token',
      description:
        'Parse the submitted token into its EVT and Key Binding JWT (KB-JWT) components, and decode their headers and payloads.',
      status: 'pending',
    },
    {
      name: 'Step 2: Validate expected values and session binding',
      description:
        'Verify the email address and verification status claims match the form submission before running cryptographic checks.',
      status: 'pending',
    },
    {
      name: 'Step 3: Validate DNS record',
      description:
        "Query the domain's DNS TXT record to check if it delegates verification authority to the token issuer.",
      status: 'pending',
    },
    {
      name: 'Step 4: Issuer discovery & JWKS fetching',
      description:
        "Fetch the issuer's well-known configuration and JWKS public keys from their authoritative origin.",
      status: 'pending',
    },
    {
      name: 'Step 5: Issuer signature verification',
      description: 'Verify the EVT signature using the fetched issuer public keys (handling optional kid).',
      status: 'pending',
    },
    {
      name: 'Step 6: Ephemeral key binding verification',
      description:
        'Verify the KB-JWT signature, session nonce, audience, and sd_hash binding using the holder confirmation key.',
      status: 'pending',
    },
  ];
}

/**
 * Full 6-step Verifier (Relying Party) validation pipeline.
 */
async function verifyEvpToken({
  rawToken,
  submittedEmail,
  expectedNonce,
  expectedAudience,
  localDnsOverrides = {},
  enforceExactEmailMatch = true,
  fetchImpl = globalThis.fetch,
  resolveTxtImpl = (hostname) => dns.resolveTxt(hostname),
  nowSeconds = Math.floor(Date.now() / 1000),
}) {
  const traceSteps = createInitialTraceSteps();

  try {
    // =========================================================================
    // STEP 1: PARSE THE TOKEN
    // =========================================================================
    traceSteps[0].inputSent = { rawToken };
    let decoded;
    try {
      decoded = decodeSdJwtPresentation(rawToken);
    } catch (err) {
      traceSteps[0].status = 'failed';
      traceSteps[0].error = err.message;
      throw new Error(`Invalid token format: ${err.message}`);
    }

    const evtHeader = decoded.evt.header;
    const evtPayload = decoded.resolvedPayload;
    const kbHeader = decoded.kbJwt.header;
    const kbPayload = decoded.kbJwt.payload;
    const iss = evtPayload.iss;

    if (!iss) {
      traceSteps[0].status = 'failed';
      traceSteps[0].error = "EVT is missing the issuer ('iss') claim.";
      throw new Error("EVT is missing the issuer ('iss') claim.");
    }

    traceSteps[0].outputReceived = {
      evtJwtDecodedHeader: evtHeader,
      evtJwtDecodedPayload: evtPayload,
      kbJwtDecodedHeader: kbHeader,
      kbJwtDecodedPayload: kbPayload,
      disclosures: decoded.disclosures,
    };
    traceSteps[0].status = 'success';

    // =========================================================================
    // STEP 2: VALIDATE EXPECTED VALUES AND SESSION BINDING
    // =========================================================================
    traceSteps[1].inputSent = {
      submittedEmail,
      tokenEmail: evtPayload.email,
      emailVerifiedClaim: evtPayload.email_verified,
      expectedNonce: expectedNonce || null,
      expectedAudience,
      enforceExactEmailMatch,
    };

    if (!expectedNonce) {
      traceSteps[1].status = 'failed';
      const msg = "Security Exception: Missing or expired session nonce ('evp_rp_nonce'). Please reload the page and try again.";
      traceSteps[1].error = msg;
      throw new Error(msg);
    }

    const emailMatches = enforceExactEmailMatch
      ? evtPayload.email === submittedEmail
      : typeof evtPayload.email === 'string' &&
        evtPayload.email.toLowerCase() === submittedEmail.toLowerCase();

    if (!emailMatches) {
      traceSteps[1].status = 'failed';
      const msg = `Email mismatch: Form input is '${submittedEmail}', but token holds '${evtPayload.email}'.`;
      traceSteps[1].error = msg;
      throw new Error(msg);
    }

    if (evtPayload.email_verified !== true) {
      traceSteps[1].status = 'failed';
      const msg = "Security Exception: The token 'email_verified' claim must be explicitly true.";
      traceSteps[1].error = msg;
      throw new Error(msg);
    }

    traceSteps[1].outputReceived = {
      localChecksPassed: true,
      details: 'Local claims matched. Proceeding to DNS delegation and cryptographic checks.',
    };
    traceSteps[1].status = 'success';

    // =========================================================================
    // STEP 3: VALIDATE DNS RECORD (_email-verification.<domain>)
    // =========================================================================
    const domain = (submittedEmail.split('@')[1] || '').toLowerCase();
    const dnsTarget = `_email-verification.${domain}`;
    traceSteps[2].inputSent = {
      submittedEmail,
      tokenIssuer: iss,
      dnsLookupTarget: dnsTarget,
    };

    let records = [];
    if (Object.prototype.hasOwnProperty.call(localDnsOverrides, domain)) {
      const overrideIss = localDnsOverrides[domain];
      records = [[`iss=${overrideIss}`]];
      traceSteps[2].serverCalled = `Localhost DNS Override Table (${dnsTarget})`;
    } else {
      traceSteps[2].serverCalled = `System DNS Server (TXT Resolve: ${dnsTarget})`;
      try {
        records = await resolveTxtImpl(dnsTarget);
      } catch (dnsErr) {
        traceSteps[2].status = 'failed';
        const msg = `DNS delegation lookup failed for ${dnsTarget}: ${dnsErr.message}`;
        traceSteps[2].error = msg;
        throw new Error(msg);
      }
    }

    let isAuthoritative = false;
    let derivedIssuerOrigin = null;

    for (const record of records) {
      const txt = Array.isArray(record) ? record.join('') : String(record);
      if (txt.startsWith('iss=')) {
        const delegatedValue = txt.substring(4).trim().replace(/\/+$/, '');
        if (delegatedValue.startsWith('http://')) {
          const parsedDelegated = new URL(delegatedValue);
          const isLocal = isLocalDevHost(parsedDelegated.hostname);
          if (!isLocal) {
            traceSteps[2].status = 'failed';
            const msg = `Security Exception: Delegated DNS issuer '${delegatedValue}' must use 'https://' scheme (plain 'http://' is only permitted for localhost).`;
            traceSteps[2].error = msg;
            throw new Error(msg);
          }
        }
        const expectedIssuer =
          delegatedValue.startsWith('https://') || delegatedValue.startsWith('http://')
            ? delegatedValue
            : `https://${delegatedValue}`;
        derivedIssuerOrigin = expectedIssuer;
        const normalizedTokenIss = String(iss).trim().replace(/\/+$/, '');
        if (normalizedTokenIss === expectedIssuer || `https://${normalizedTokenIss}` === expectedIssuer) {
          isAuthoritative = true;
          break;
        }
      }
    }

    traceSteps[2].outputReceived = {
      dnsTxtRecords: records,
      derivedIssuerOrigin,
      exactOriginMatch: isAuthoritative,
    };

    if (!isAuthoritative) {
      traceSteps[2].status = 'failed';
      const msg = `Security Exception: Issuer '${iss}' is not authoritative for the email domain '${domain}' (DNS delegated: '${derivedIssuerOrigin || 'none'}').`;
      traceSteps[2].error = msg;
      throw new Error(msg);
    }
    traceSteps[2].status = 'success';

    // =========================================================================
    // STEP 4: ISSUER DISCOVERY & JWKS FETCHING
    // =========================================================================
    const normalizedIss =
      iss.startsWith('https://') || iss.startsWith('http://') ? iss.replace(/\/+$/, '') : `https://${iss.replace(/\/+$/, '')}`;
    const discoveryUrl = `${normalizedIss}/.well-known/email-verification`;
    traceSteps[3].serverCalled = discoveryUrl;
    traceSteps[3].inputSent = { url: discoveryUrl };

    if (!isSafeIssuerUrl(discoveryUrl)) {
      traceSteps[3].status = 'failed';
      const msg = `Security Exception: Unsafe or invalid discovery URL '${discoveryUrl}'.`;
      traceSteps[3].error = msg;
      throw new Error(msg);
    }

    const metadataRes = await fetchImpl(discoveryUrl);
    if (!metadataRes.ok) {
      traceSteps[3].status = 'failed';
      const msg = `Failed to discover issuer metadata at ${discoveryUrl}: HTTP ${metadataRes.status}`;
      traceSteps[3].error = msg;
      throw new Error(msg);
    }
    const metadata = await metadataRes.json();

    const normalizedMetaIssuer = metadata.issuer ? String(metadata.issuer).replace(/\/+$/, '') : '';
    if (normalizedMetaIssuer && normalizedMetaIssuer !== normalizedIss && metadata.issuer !== iss) {
      traceSteps[3].status = 'failed';
      const msg = `Issuer metadata validation failed at ${discoveryUrl}: expected issuer '${normalizedIss}', got '${metadata.issuer}'.`;
      traceSteps[3].error = msg;
      throw new Error(msg);
    }

    const jwksUri = metadata.jwks_uri;
    if (!jwksUri || !isSafeIssuerUrl(jwksUri)) {
      traceSteps[3].status = 'failed';
      const msg = `Issuer metadata at ${discoveryUrl} has a missing or unsafe 'jwks_uri'.`;
      traceSteps[3].error = msg;
      throw new Error(msg);
    }

    traceSteps[3].serverCalled = `${discoveryUrl} & ${jwksUri}`;
    const jwksRes = await fetchImpl(jwksUri);
    if (!jwksRes.ok) {
      traceSteps[3].status = 'failed';
      const msg = `Failed to fetch JWKS from ${jwksUri}: HTTP ${jwksRes.status}`;
      traceSteps[3].error = msg;
      throw new Error(msg);
    }
    const jwksData = await jwksRes.json();
    traceSteps[3].outputReceived = {
      issuerMetadata: metadata,
      issuerJWKS: jwksData,
    };
    traceSteps[3].status = 'success';

    // =========================================================================
    // STEP 5: ISSUER SIGNATURE VERIFICATION (EVT)
    // =========================================================================
    const allowedAlgs = ['Ed25519', 'EdDSA', 'ES256'];
    const evtAlg = evtHeader.alg;
    const allowedEvtTyps = ['evt+jwt', 'evp+sd-jwt', 'sd+jwt'];

    traceSteps[4].inputSent = {
      signingAlg: evtAlg,
      typ: evtHeader.typ,
      kid: evtHeader.kid || null,
      candidateKeyCount: Array.isArray(jwksData.keys) ? jwksData.keys.length : 0,
    };

    if (!evtAlg || !allowedAlgs.includes(evtAlg)) {
      traceSteps[4].status = 'failed';
      const msg = `Security Exception: Unsupported or insecure EVT signing algorithm '${evtAlg || 'none'}'.`;
      traceSteps[4].error = msg;
      throw new Error(msg);
    }

    if (evtHeader.typ && !allowedEvtTyps.includes(evtHeader.typ)) {
      traceSteps[4].status = 'failed';
      const msg = `Security Exception: Unexpected EVT header typ '${evtHeader.typ}'. Expected 'evt+jwt'.`;
      traceSteps[4].error = msg;
      throw new Error(msg);
    }

    // Handle optional `kid` in EVT and/or JWKS: prioritize kid-matching keys first when kid is present,
    // then fall back to remaining JWKS keys (supporting Gmail kid omission and JWKS key rotation)
    const allKeys = Array.isArray(jwksData.keys) ? jwksData.keys : [];
    const keysToTry = evtHeader.kid
      ? [
          ...allKeys.filter((k) => k.kid === evtHeader.kid),
          ...allKeys.filter((k) => k.kid !== evtHeader.kid),
        ]
      : allKeys;

    if (keysToTry.length === 0) {
      traceSteps[4].status = 'failed';
      const msg = evtHeader.kid
        ? `No key with kid '${evtHeader.kid}' found in issuer JWKS.`
        : 'Issuer JWKS contains no keys.';
      traceSteps[4].error = msg;
      throw new Error(msg);
    }

    let evtVerifiedWithKey = null;
    for (const jwk of keysToTry) {
      try {
        verifyCompactJws(decoded.evt.raw, jwk, jwk.alg || evtAlg);
        evtVerifiedWithKey = jwk.kid || 'matched-key-without-kid';
        break;
      } catch {
        continue;
      }
    }

    if (!evtVerifiedWithKey) {
      traceSteps[4].status = 'failed';
      const msg = 'EVT cryptographic signature verification failed against all candidate JWKS keys.';
      traceSteps[4].error = msg;
      throw new Error(msg);
    }

    try {
      validateTimeClaims(evtPayload, 300, 60, nowSeconds);
    } catch (timeErr) {
      traceSteps[4].status = 'failed';
      traceSteps[4].error = timeErr.message;
      throw timeErr;
    }

    traceSteps[4].outputReceived = {
      cryptographicallyVerified: true,
      matchedKey: evtVerifiedWithKey,
      kidWasPresentInEvtHeader: Boolean(evtHeader.kid),
    };
    traceSteps[4].status = 'success';

    // =========================================================================
    // STEP 6: EPHEMERAL KEY BINDING VERIFICATION (KB-JWT)
    // =========================================================================
    const kbAlg = kbHeader.alg;
    const browserJwk = evtPayload.cnf && evtPayload.cnf.jwk;

    traceSteps[5].inputSent = {
      cnf: evtPayload.cnf,
      kbSigningAlg: kbAlg,
      kbTyp: kbHeader.typ,
      expectedAudience,
      expectedNonce,
    };

    if (!kbAlg || !allowedAlgs.includes(kbAlg)) {
      traceSteps[5].status = 'failed';
      const msg = `Security Exception: Unsupported or insecure KB-JWT signing algorithm '${kbAlg || 'none'}'.`;
      traceSteps[5].error = msg;
      throw new Error(msg);
    }

    if (kbHeader.typ !== 'kb+jwt') {
      traceSteps[5].status = 'failed';
      const msg = `Security Exception: Invalid KB-JWT header typ '${kbHeader.typ}'. Expected 'kb+jwt'.`;
      traceSteps[5].error = msg;
      throw new Error(msg);
    }

    if (!browserJwk || typeof browserJwk !== 'object') {
      traceSteps[5].status = 'failed';
      const msg = "Security Exception: EVT payload is missing holder confirmation key ('cnf.jwk').";
      traceSteps[5].error = msg;
      throw new Error(msg);
    }

    // Reject private key material ('d') inside cnf.jwk (RFC 7800 / RFC 9901 security requirement)
    if (browserJwk.d || browserJwk.p || browserJwk.q) {
      traceSteps[5].status = 'failed';
      const msg = "Security Exception: EVT holder confirmation key ('cnf.jwk') must not expose private key material ('d').";
      traceSteps[5].error = msg;
      throw new Error(msg);
    }

    const normalizeAlg = (a) => (a === 'Ed25519' ? 'EdDSA' : a);
    if (browserJwk.alg && normalizeAlg(kbAlg) !== normalizeAlg(browserJwk.alg)) {
      traceSteps[5].status = 'failed';
      const msg = `Security Exception: KB-JWT signing algorithm ('${kbAlg}') does not match EVT cnf.jwk.alg ('${browserJwk.alg}').`;
      traceSteps[5].error = msg;
      throw new Error(msg);
    }

    try {
      verifyCompactJws(decoded.kbJwt.raw, browserJwk, kbAlg);
    } catch (kbSigErr) {
      traceSteps[5].status = 'failed';
      const msg = `KB-JWT holder signature verification failed: ${kbSigErr.message}`;
      traceSteps[5].error = msg;
      throw new Error(msg);
    }

    // Verify audience, nonce, iat, and sd_hash
    if (kbPayload.aud !== expectedAudience) {
      traceSteps[5].status = 'failed';
      const msg = `KB-JWT audience mismatch: expected '${expectedAudience}', got '${kbPayload.aud}'.`;
      traceSteps[5].error = msg;
      throw new Error(msg);
    }

    if (kbPayload.nonce !== expectedNonce) {
      traceSteps[5].status = 'failed';
      const msg = `KB-JWT nonce mismatch: expected '${expectedNonce}', got '${kbPayload.nonce}'.`;
      traceSteps[5].error = msg;
      throw new Error(msg);
    }

    try {
      validateTimeClaims(kbPayload, 300, 60, nowSeconds);
    } catch (kbTimeErr) {
      traceSteps[5].status = 'failed';
      traceSteps[5].error = kbTimeErr.message;
      throw kbTimeErr;
    }

    const calculatedSdHash = crypto
      .createHash('sha256')
      .update(decoded.sdHashInput, 'ascii')
      .digest('base64url');

    if (kbPayload.sd_hash !== calculatedSdHash) {
      traceSteps[5].status = 'failed';
      const msg = `KB-JWT sd_hash mismatch: expected '${calculatedSdHash}' (SHA-256 of '<EVT>~'), got '${kbPayload.sd_hash}'.`;
      traceSteps[5].error = msg;
      throw new Error(msg);
    }

    traceSteps[5].outputReceived = {
      kbJwtSignatureVerified: true,
      audienceVerified: kbPayload.aud,
      nonceVerified: kbPayload.nonce,
      sdHashVerified: calculatedSdHash,
    };
    traceSteps[5].status = 'success';

    return {
      verified: true,
      email: evtPayload.email,
      issuer: normalizedIss,
      evt: evtPayload,
      kb: kbPayload,
      traceSteps,
    };
  } catch (err) {
    return {
      verified: false,
      error: err.message,
      traceSteps,
    };
  }
}

/**
 * RFC 9421 HTTP Message Signature & RFC 8941 Structured Field helpers.
 *
 * Parses `Signature-Key: sig=hwk;crv="Ed25519";kty="OKP";x="..."`
 * or unquoted RFC 8941 tokens `sig=hwk;crv=Ed25519;kty=OKP;x=...`
 * as well as EC P-256 keys (`kty="EC";crv="P-256";x="...";y="..."`).
 */
function parseSignatureKeyHwk(signatureKeyHeader) {
  if (!signatureKeyHeader || !/(?:^|,|\s)sig=hwk(?:;|$)/i.test(signatureKeyHeader.trim())) {
    throw new Error("Signature-Key header does not use the 'sig=hwk' scheme or is missing.");
  }
  const getParam = (name) => {
    const match = signatureKeyHeader.match(new RegExp(`(?:;|,)\\s*${name}=(?:"([^"]+)"|([^\\s;,]+))`));
    return match ? (match[1] ?? match[2]) : undefined;
  };
  const kty = getParam('kty');
  const crv = getParam('crv');
  const x = getParam('x');
  const y = getParam('y');
  const d = getParam('d');
  const alg = getParam('alg');

  if (d) {
    throw new Error("Signature-Key header must not contain private key parameter 'd'.");
  }

  const supportedAlgs = ['Ed25519', 'EdDSA', 'ES256'];
  if (alg && !supportedAlgs.includes(alg)) {
    const err = new Error(`Unsupported algorithm '${alg}' in Signature-Key header.`);
    err.signatureErrorCode = 'unsupported_algorithm';
    throw err;
  }

  if (!kty || !x) {
    throw new Error("Signature-Key header is missing required 'kty' or 'x' parameters.");
  }

  if (kty === 'OKP') {
    if (crv && crv !== 'Ed25519') {
      throw new Error(`Unsupported OKP curve in Signature-Key: '${crv}'. Expected 'Ed25519'.`);
    }
    return {
      kty: 'OKP',
      crv: crv || 'Ed25519',
      x,
      alg: alg || 'EdDSA',
    };
  }

  if (kty === 'EC') {
    if (crv !== 'P-256' || !y) {
      throw new Error("Signature-Key header for EC (P-256) key requires crv='P-256' and both 'x' and 'y' coordinates.");
    }
    return {
      kty: 'EC',
      crv: 'P-256',
      x,
      y,
      alg: alg || 'ES256',
    };
  }

  throw new Error(`Unsupported Signature-Key kty '${kty}'. Expected 'OKP' (Ed25519) or 'EC' (P-256).`);
}

/**
 * Extracts the ordered list of covered component identifiers and signature parameters
 * from `Signature-Input: sig=("@method" ...);created=1780000000` (including optional
 * additional RFC 9421 structured field parameters such as `;alg="ed25519";keyid="..."`
 * or multi-signature comma-separated headers `sig1=..., sig=(...)`).
 */
function extractSignatureInputParams(signatureInputValue) {
  if (!signatureInputValue || typeof signatureInputValue !== 'string') {
    throw new Error('Missing Signature-Input header.');
  }
  // Support multi-signature headers by extracting the `sig=(...)` dictionary member if present
  let targetMember = signatureInputValue.trim();
  const sigMemberMatch = targetMember.match(/(?:^|,)\s*sig=(\([^)]*\)[^,]*)/);
  const paramsPart = sigMemberMatch ? sigMemberMatch[1].trim() : targetMember.replace(/^sig=/, '').trim();

  const listMatch = paramsPart.match(/^\(([^)]*)\)(.*)$/);
  if (!listMatch) {
    throw new Error("Malformed Signature-Input header: missing parenthesized component list '(...)'.");
  }
  const innerList = listMatch[1].trim();
  const tailParams = listMatch[2] || '';

  const components = [];
  const itemRegex = /"([^"]+)"/g;
  let m;
  while ((m = itemRegex.exec(innerList)) !== null) {
    components.push(m[1]);
  }

  const createdMatch = tailParams.match(/(?:^|;)\s*created=(\d+)/);
  if (!createdMatch) {
    throw new Error("Signature-Input header is missing required ';created=<timestamp>' parameter.");
  }
  const created = Number(createdMatch[1]);

  // Verify required components are covered
  const compSet = new Set(components);
  const hasTarget = compSet.has('@target-uri') || (compSet.has('@authority') && compSet.has('@path'));
  if (!compSet.has('@method') || !hasTarget || !compSet.has('content-digest') || !compSet.has('signature-key')) {
    throw new Error(
      "Signature-Input is missing required EVP covered components ('@method', '@target-uri' or '@authority'+'@path', 'content-digest', 'signature-key')."
    );
  }

  return {
    paramsPart,
    components,
    created,
  };
}

/**
 * Dynamically constructs the RFC 9421 signature base in the exact component order
 * specified by `Signature-Input`.
 */
function buildRfc9421SignatureBase({
  method = 'POST',
  authority = 'localhost:3000',
  path = '/email-verification/issuance',
  targetUri,
  scheme = 'http',
  contentDigest,
  signatureKey,
  secFetchDest = 'email-verification',
  headers = {},
  signatureInputValue,
}) {
  const { paramsPart, components } = extractSignatureInputParams(signatureInputValue);
  const resolvedTargetUri = targetUri || `${scheme}://${authority}${path}`;

  const getLowerHeader = (name) => {
    const lower = name.toLowerCase();
    for (const [k, v] of Object.entries(headers || {})) {
      if (k.toLowerCase() === lower) return String(v);
    }
    return undefined;
  };

  const lines = components.map((comp) => {
    switch (comp) {
      case '@method':
        return `"@method": ${method.toUpperCase()}`;
      case '@authority':
        return `"@authority": ${authority}`;
      case '@path':
        return `"@path": ${path}`;
      case '@scheme':
        return `"@scheme": ${scheme}`;
      case '@target-uri':
        return `"@target-uri": ${resolvedTargetUri}`;
      case 'content-digest':
        return `"content-digest": ${contentDigest ?? getLowerHeader('content-digest')}`;
      case 'signature-key':
        return `"signature-key": ${signatureKey ?? getLowerHeader('signature-key')}`;
      case 'sec-fetch-dest':
        return `"sec-fetch-dest": ${secFetchDest ?? getLowerHeader('sec-fetch-dest')}`;
      default: {
        const val = getLowerHeader(comp);
        if (val === undefined) {
          throw new Error(`Covered component '${comp}' in Signature-Input is missing from request headers.`);
        }
        return `"${comp}": ${val}`;
      }
    }
  });

  lines.push(`"@signature-params": ${paramsPart}`);
  return lines.join('\n');
}

const buildSignatureBase = buildRfc9421SignatureBase;

/**
 * Localhost Mock Issuer: Handles `POST /email-verification/issuance`
 * Supports both:
 * - Path A (Chrome 153/154+): `application/json` with RFC 9421 HTTP Message Signatures (`Signature`, `Signature-Input`, `Signature-Key`, `Content-Digest`) and `Sec-Fetch-Dest: email-verification` (or `emailverification`)
 * - Path B (Legacy Chrome 150-152): `application/x-www-form-urlencoded` with `request_token` JWT
 */
function handleIssuanceRequest({
  method = 'POST',
  authority,
  path = '/email-verification/issuance',
  headers,
  rawBody,
  isSessionLoggedIn,
  allowedEmails,
  issuerOrigin = 'http://localhost:3000',
  issuerKeyPair,
  includeKidInEvt = true,
  nowSeconds = Math.floor(Date.now() / 1000),
}) {
  const effectiveIssuerKeyPair = issuerKeyPair || createMockIssuerKeys('EdDSA');
  const getHeader = (name) => {
    const lower = name.toLowerCase();
    for (const [k, v] of Object.entries(headers || {})) {
      if (k.toLowerCase() === lower) return String(v);
    }
    return undefined;
  };

  // 1. Validate Sec-Fetch-Dest (Chrome 154+: `email-verification`, Chrome 153: `emailverification`)
  const allowedSecFetchDest = new Set(['email-verification', 'emailverification', 'webidentity', 'empty']);
  const secFetchDest = getHeader('sec-fetch-dest');
  if (secFetchDest && !allowedSecFetchDest.has(secFetchDest)) {
    return {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
      body: {
        error: 'invalid_request',
        error_description: `Invalid Sec-Fetch-Dest header: '${secFetchDest}'. Expected 'email-verification'.`,
      },
    };
  }

  const contentType = getHeader('content-type') || '';
  const signatureHeader = getHeader('signature');
  const signatureInputHeader = getHeader('signature-input');
  const signatureKeyHeader = getHeader('signature-key');
  const contentDigestHeader = getHeader('content-digest');

  let requestedEmail = '';
  let browserJwk = null;

  if (signatureHeader || signatureInputHeader || signatureKeyHeader) {
    // Path A: RFC 9421 HTTP Message Signatures (Chrome 153+)
    if (!signatureHeader || !signatureInputHeader || !signatureKeyHeader) {
      return {
        status: 400,
        headers: { 'Content-Type': 'application/json', 'Signature-Error': 'error=invalid_signature' },
        body: {
          error: 'invalid_signature',
          error_description: 'Missing required HTTP Message Signature headers (Signature, Signature-Input, or Signature-Key).',
        },
      };
    }

    if (!contentType.includes('application/json')) {
      return {
        status: 415,
        headers: { 'Content-Type': 'application/json' },
        body: {
          error: 'invalid_request',
          error_description: 'Content-Type must be application/json.',
        },
      };
    }

    if (!contentDigestHeader) {
      return {
        status: 400,
        headers: { 'Content-Type': 'application/json', 'Signature-Error': 'error=invalid_signature' },
        body: {
          error: 'invalid_signature',
          error_description: 'Missing required Content-Digest header.',
        },
      };
    }

    const expectedDigest = `sha-256=:${crypto.createHash('sha256').update(rawBody || '', 'utf8').digest('base64')}:`;
    if (!contentDigestHeader.includes(expectedDigest)) {
      return {
        status: 400,
        headers: { 'Content-Type': 'application/json', 'Signature-Error': 'error=invalid_signature' },
        body: {
          error: 'invalid_signature',
          error_description: `Content-Digest verification failed. Expected ${expectedDigest}.`,
        },
      };
    }

    try {
      browserJwk = parseSignatureKeyHwk(signatureKeyHeader);
    } catch (err) {
      const errCode = err.signatureErrorCode || 'invalid_signature';
      return {
        status: 400,
        headers: { 'Content-Type': 'application/json', 'Signature-Error': `error=${errCode}` },
        body: {
          error: 'invalid_signature',
          error_description: err.message,
        },
      };
    }

    // Verify the RFC 9421 signature over the dynamically ordered signature base
    const sigMatch = signatureHeader.match(/sig=:([^:]+):/);
    if (!sigMatch) {
      return {
        status: 400,
        headers: { 'Content-Type': 'application/json', 'Signature-Error': 'error=invalid_signature' },
        body: {
          error: 'invalid_signature',
          error_description: "Malformed Signature header (expected 'sig=:<base64>:').",
        },
      };
    }

    const resolvedAuthority = authority || getHeader('host') || new URL(issuerOrigin).host;
    const resolvedScheme = issuerOrigin.startsWith('https://') ? 'https' : 'http';
    const targetUri = `${issuerOrigin.replace(/\/$/, '')}${path}`;
    const effectiveSecFetchDest =
      secFetchDest && secFetchDest !== 'empty'
        ? secFetchDest
        : getHeader('x-evp-sec-fetch-dest') || 'email-verification';

    let sigBase;
    try {
      sigBase = buildRfc9421SignatureBase({
        method,
        authority: resolvedAuthority,
        path,
        targetUri,
        scheme: resolvedScheme,
        contentDigest: contentDigestHeader,
        signatureKey: signatureKeyHeader,
        secFetchDest: effectiveSecFetchDest,
        headers,
        signatureInputValue: signatureInputHeader,
      });
    } catch (inputErr) {
      return {
        status: 400,
        headers: { 'Content-Type': 'application/json', 'Signature-Error': 'error=invalid_signature' },
        body: {
          error: 'invalid_signature',
          error_description: inputErr.message,
        },
      };
    }

    const sigBytes = Buffer.from(sigMatch[1], 'base64');

    try {
      const pubKey = crypto.createPublicKey({
        key: { kty: browserJwk.kty, crv: browserJwk.crv, x: browserJwk.x, ...(browserJwk.y ? { y: browserJwk.y } : {}) },
        format: 'jwk',
      });
      const verifyBase = (baseStr) =>
        browserJwk.crv === 'P-256'
          ? crypto.verify('sha256', Buffer.from(baseStr, 'utf8'), { key: pubKey, dsaEncoding: 'ieee-p1363' }, sigBytes)
          : crypto.verify(null, Buffer.from(baseStr, 'utf8'), pubKey, sigBytes);

      let isValid = verifyBase(sigBase);
      if (!isValid && effectiveSecFetchDest === 'emailverification') {
        const altBase = buildRfc9421SignatureBase({
          method,
          authority: resolvedAuthority,
          path,
          targetUri,
          scheme: resolvedScheme,
          contentDigest: contentDigestHeader,
          signatureKey: signatureKeyHeader,
          secFetchDest: 'email-verification',
          headers,
          signatureInputValue: signatureInputHeader,
        });
        isValid = verifyBase(altBase);
      }
      if (!isValid) {
        throw new Error('Signature bytes did not verify against Signature-Key public key.');
      }
    } catch (sigErr) {
      return {
        status: 400,
        headers: { 'Content-Type': 'application/json', 'Signature-Error': 'error=invalid_signature' },
        body: {
          error: 'invalid_signature',
          error_description: `RFC 9421 HTTP Message Signature verification failed: ${sigErr.message}`,
        },
      };
    }

    try {
      const parsedBody = JSON.parse(rawBody || '{}');
      requestedEmail = parsedBody.email;
    } catch {
      return {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
        body: {
          error: 'invalid_request',
          error_description: 'Invalid JSON body in issuance request.',
        },
      };
    }
  } else {
    // Path B: Legacy `request_token` in `application/x-www-form-urlencoded`
    const params = new URLSearchParams(rawBody || '');
    const requestToken = params.get('request_token');
    if (!requestToken) {
      return {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
        body: {
          error: 'invalid_request',
          error_description: 'Missing HTTP Message Signature headers or request_token parameter.',
        },
      };
    }
    try {
      const pieces = requestToken.split('.');
      const header = JSON.parse(fromBase64UrlToString(pieces[0]));
      if (!header.jwk) throw new Error('Missing jwk in request_token header');
      const verified = verifyCompactJws(requestToken, header.jwk, header.alg);
      browserJwk = header.jwk;
      requestedEmail = verified.payload.email;
    } catch (err) {
      return {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
        body: {
          error: 'invalid_signature',
          error_description: `Legacy request_token verification failed: ${err.message}`,
        },
      };
    }
  }

  if (!requestedEmail) {
    return {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
      body: {
        error: 'invalid_request',
        error_description: "Missing required 'email' field in request.",
      },
    };
  }

  // 2. Check session authentication and email ownership (case-insensitive check for account ownership,
  //    but return exact email casing from request per Chrome 156 spec!)
  const reqEmailLower = requestedEmail.toLowerCase();
  const reqDomainLower = reqEmailLower.slice(reqEmailLower.lastIndexOf('@') + 1);
  const isEmailOwned = (allowedEmails || []).some((entry) => {
    const lower = String(entry).toLowerCase();
    if (lower.startsWith('*@')) {
      return reqDomainLower === lower.slice(2);
    }
    return lower === reqEmailLower;
  });

  if (!isSessionLoggedIn || !isEmailOwned) {
    return {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
      body: {
        error: 'authentication_required',
        error_description: 'User must be authenticated with the provider and own the requested email address.',
      },
    };
  }

  // 3. Issue Email Verification Token (EVT) using the Issuer's configured algorithm (EdDSA or ES256)
  const issuerAlg =
    effectiveIssuerKeyPair.alg ||
    effectiveIssuerKeyPair.publicJwk?.alg ||
    (effectiveIssuerKeyPair.publicJwk?.kty === 'EC' ? 'ES256' : 'EdDSA');

  const evtHeader = {
    alg: issuerAlg,
    typ: 'evt+jwt',
  };
  if (includeKidInEvt && effectiveIssuerKeyPair.publicJwk.kid) {
    evtHeader.kid = effectiveIssuerKeyPair.publicJwk.kid;
  }

  const evtPayload = {
    iss: issuerOrigin,
    iat: nowSeconds,
    exp: nowSeconds + 300,
    cnf: {
      jwk: browserJwk,
    },
    email: requestedEmail, // Returned exactly as requested (Chrome 156 requirement)
    email_verified: true,
  };

  const evtJwt = signCompactJws(evtHeader, evtPayload, effectiveIssuerKeyPair.privateKey);
  const issuanceToken = `${evtJwt}~`;

  return {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    body: {
      issuance_token: issuanceToken,
    },
  };
}

/**
 * Browser Simulator for Localhost Testing:
 * Executes the exact steps Chrome performs when an email is entered into a form with
 * `<input type="hidden" name="token" nonce="..." autocomplete="email-verification-token">`.
 * Defaults to Chrome 154–156's RFC 9421 `Signature-Input` covered components:
 * `("@method" "@target-uri" "content-digest" "sec-fetch-dest" "signature-key")`
 * while supporting custom component orderings (including Chrome 153's
 * `("@method" "@authority" "@path" "content-digest" "signature-key")`),
 * both 'EdDSA' (Ed25519) and 'ES256' (ECDSA P-256) holder keys,
 * and quoted/unquoted RFC 8941 `Signature-Key` parameter serialization.
 */
function simulateBrowserEvpFlow({
  email,
  nonce,
  verifierOrigin,
  issuerOrigin,
  issuerKeyPair,
  holderAlg = 'EdDSA',
  componentOrder,
  customComponentOrder,
  secFetchDest = 'email-verification',
  unquotedSignatureKey = false,
  isSessionLoggedIn = true,
  allowedEmails = [email, '*@localhost.example'],
  includeKidInEvt = true,
  nowSeconds = Math.floor(Date.now() / 1000),
}) {
  const effectiveIssuerKeyPair = issuerKeyPair || createMockIssuerKeys('EdDSA');
  // 1. Ephemeral browser holder keypair ('EdDSA' or 'ES256')
  const holder =
    holderAlg === 'ES256'
      ? generateP256KeyPairJwk(null, false)
      : generateEd25519KeyPairJwk(null, false);

  const rawBody = JSON.stringify({ email });
  const contentDigest = `sha-256=:${crypto.createHash('sha256').update(rawBody, 'utf8').digest('base64')}:`;

  let signatureKey;
  if (holderAlg === 'ES256') {
    signatureKey = unquotedSignatureKey
      ? `sig=hwk;crv=P-256;kty=EC;x=${holder.publicJwk.x};y=${holder.publicJwk.y}`
      : `sig=hwk;crv="P-256";kty="EC";x="${holder.publicJwk.x}";y="${holder.publicJwk.y}"`;
  } else {
    signatureKey = unquotedSignatureKey
      ? `sig=hwk;crv=Ed25519;kty=OKP;x=${holder.publicJwk.x}`
      : `sig=hwk;crv="Ed25519";kty="OKP";x="${holder.publicJwk.x}"`;
  }

  const effectiveOrder = componentOrder || customComponentOrder;
  const orderedComponents = Array.isArray(effectiveOrder) && effectiveOrder.length > 0
    ? effectiveOrder
    : ['@method', '@target-uri', 'content-digest', 'sec-fetch-dest', 'signature-key'];

  const serializedComponents = orderedComponents.map((c) => `"${c}"`).join(' ');
  const signatureInput = `sig=(${serializedComponents});created=${nowSeconds}`;

  const parsedIssuerUrl = new URL(issuerOrigin);
  const authority = parsedIssuerUrl.host;
  const scheme = parsedIssuerUrl.protocol.replace(':', '');
  const path = '/email-verification/issuance';
  const targetUri = `${issuerOrigin.replace(/\/$/, '')}${path}`;

  const sigBase = buildRfc9421SignatureBase({
    method: 'POST',
    authority,
    path,
    targetUri,
    scheme,
    contentDigest,
    signatureKey,
    secFetchDest,
    signatureInputValue: signatureInput,
  });

  const sigBuf =
    holderAlg === 'ES256'
      ? crypto.sign('sha256', Buffer.from(sigBase, 'utf8'), {
          key: holder.privateKey,
          dsaEncoding: 'ieee-p1363',
        })
      : crypto.sign(null, Buffer.from(sigBase, 'utf8'), holder.privateKey);

  const sigB64 = sigBuf.toString('base64');
  const signatureHeader = `sig=:${sigB64}:`;

  // 2. Call Issuer's issuance handler
  const issuanceResponse = handleIssuanceRequest({
    method: 'POST',
    authority,
    path,
    headers: {
      'Content-Type': 'application/json',
      'Sec-Fetch-Dest': secFetchDest,
      'Content-Digest': contentDigest,
      'Signature-Key': signatureKey,
      'Signature-Input': signatureInput,
      Signature: signatureHeader,
    },
    rawBody,
    isSessionLoggedIn,
    allowedEmails,
    issuerOrigin,
    issuerKeyPair: effectiveIssuerKeyPair,
    includeKidInEvt,
    nowSeconds,
  });

  if (issuanceResponse.status !== 200 || !issuanceResponse.body.issuance_token) {
    throw new Error(
      `Issuer issuance failed (HTTP ${issuanceResponse.status}): ${
        issuanceResponse.body.error_description || issuanceResponse.body.error
      }`
    );
  }

  const issuanceToken = issuanceResponse.body.issuance_token; // `<evtJwt>~`
  const sdHash = crypto.createHash('sha256').update(issuanceToken, 'ascii').digest('base64url');

  // 3. Sign Key Binding JWT (KB-JWT) with the ephemeral holder private key
  const kbHeader = {
    alg: holderAlg === 'ES256' ? 'ES256' : 'EdDSA',
    typ: 'kb+jwt',
  };
  const kbPayload = {
    aud: verifierOrigin,
    nonce,
    iat: nowSeconds,
    sd_hash: sdHash,
  };

  const kbJwt = signCompactJws(kbHeader, kbPayload, holder.privateKey);
  const presentationToken = `${issuanceToken}${kbJwt}`;

  return {
    presentationToken,
    presentation_token: presentationToken,
    issuanceRequestHeaders: {
      'Sec-Fetch-Dest': 'email-verification',
      'Content-Type': 'application/json',
      'Content-Digest': contentDigest,
      'Signature-Key': signatureKey,
      'Signature-Input': signatureInput,
      Signature: signatureHeader,
    },
    issuanceRequestBody: rawBody,
  };
}

module.exports = {
  toBase64Url,
  fromBase64UrlToString,
  generateEd25519KeyPairJwk,
  generateP256KeyPairJwk,
  createMockIssuerKeys,
  signCompactJws,
  verifyCompactJws,
  decodeSdJwtPresentation,
  validateTimeClaims,
  isSafeIssuerUrl,
  createInitialTraceSteps,
  verifyEvpToken,
  parseSignatureKeyHwk,
  extractSignatureInputParams,
  buildRfc9421SignatureBase,
  buildSignatureBase,
  handleIssuanceRequest,
  simulateBrowserEvpFlow,
};
