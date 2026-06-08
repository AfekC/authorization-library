const { generateKeyPair, exportJWK, SignJWT } = require("jose");
const crypto = require("crypto");

/**
 * One RSA keypair for the Auth Service (user JWTs) and one for the SSO provider
 * (service tokens). Each exposes a JWKS; both libraries verify against them.
 *
 * Key rotation (G13):
 *   issuer.rotate()          — Generate a new keypair, publish old+new in JWKS,
 *                              and start signing with the new kid. Returns the new kid.
 *   issuer.retireOldKeys()   — Drop all keys except the current signing key from the
 *                              JWKS (call after the overlap window has elapsed).
 *   issuer.signingKid        — The kid currently used to sign new tokens (getter).
 *   issuer.jwks              — Live JWKS document (getter, always current).
 *
 * Invalid-token minting (G6):
 *   issuer.signInvalid(claims, opts)
 *                            — Mint a token that is deliberately broken. opts.mode:
 *     "expired"          — iat and exp both in the past (expired 5 min ago),
 *                          signed with the real private key so only exp is wrong.
 *     "wrongSignature"   — signed with a throwaway key not in the JWKS.
 *     "wrongTokenUse"    — valid token but token_use = "INVALID_USE".
 *     "missingTokenUse"  — correctly signed, non-expired token, no token_use claim.
 *     "missingClaims"    — omits iss/aud/exp; bare header+payload, bogus signature.
 *     "malformed"        — returns the literal string "not.a.jwt".
 */
async function createIssuer(issuer, initialKid) {
  // All active keypairs: kid -> { privateKey, publicJwk }
  const keyring = new Map();

  async function _generateKey(kid) {
    const { publicKey, privateKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    jwk.kid = kid;
    jwk.use = "sig";
    jwk.alg = "RS256";
    keyring.set(kid, { privateKey, publicJwk: jwk });
  }

  await _generateKey(initialKid);
  let _signingKid = initialKid;

  // Build the JWKS document from all keys currently in the keyring.
  function _buildJwks() {
    return { keys: Array.from(keyring.values()).map((e) => e.publicJwk) };
  }

  // Sign `data` (ASCII string "header.payload") with RSA-PKCS1 using Node crypto.
  // Returns base64url-encoded signature. Used only for the "expired" path where
  // jose's SignJWT enforces a future exp and would reject a backdated one.
  function _signRaw(privateKey, data) {
    const sig = crypto.sign("sha256", Buffer.from(data), {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    });
    return sig.toString("base64url");
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /** Rotate: generate a new keypair, add to JWKS alongside old keys, switch signing. */
  async function rotate() {
    const newKid = `${initialKid}-rot${Date.now()}`;
    await _generateKey(newKid);
    _signingKid = newKid;
    console.log(
      `[keys] rotated ${issuer}: signing kid is now ${newKid}, JWKS has ${keyring.size} key(s)`,
    );
    return newKid;
  }

  /** Retire all keys except the current signing key (call after the overlap window). */
  function retireOldKeys() {
    const retained = _signingKid;
    for (const kid of keyring.keys()) {
      if (kid !== retained) keyring.delete(kid);
    }
    console.log(`[keys] retired old keys for ${issuer}; only ${retained} remains`);
  }

  /** Normal token signing (uses the current signing key). */
  async function sign(claims, { audience, expiresIn = "10m" } = {}) {
    const { privateKey } = keyring.get(_signingKid);
    let b = new SignJWT(claims)
      .setProtectedHeader({ alg: "RS256", kid: _signingKid })
      .setIssuedAt()
      .setIssuer(issuer)
      .setExpirationTime(expiresIn);
    if (audience) b = b.setAudience(audience);
    return b.sign(privateKey);
  }

  /**
   * Mint a deliberately broken token for adverse-condition / G6 testing.
   * @param {object} claims  Base payload claims (e.g. { sub, role }).
   * @param {{ mode?: string, audience?: string }} opts
   * @returns {Promise<string>} The broken JWT (or literal "not.a.jwt").
   */
  async function signInvalid(claims = {}, { mode = "expired", audience } = {}) {
    switch (mode) {
      case "malformed":
        return "not.a.jwt";

      case "missingClaims": {
        // No iss, aud, or exp. Signature is structurally present but bogus.
        const hdr = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
        const pld = Buffer.from(JSON.stringify(claims)).toString("base64url");
        return `${hdr}.${pld}.invalidsignature`;
      }

      case "wrongSignature": {
        // Signed with a throwaway key that is NOT in the JWKS.
        const { privateKey: throwaway } = await generateKeyPair("RS256");
        let b = new SignJWT({ ...claims })
          .setProtectedHeader({ alg: "RS256", kid: _signingKid })
          .setIssuedAt()
          .setIssuer(issuer)
          .setExpirationTime("10m");
        if (audience) b = b.setAudience(audience);
        return b.sign(throwaway);
      }

      case "expired": {
        // iat and exp both in the past; signature is real (only timing is wrong).
        const { privateKey } = keyring.get(_signingKid);
        const nowSec = Math.floor(Date.now() / 1000);
        const expiredPayload = {
          ...claims,
          iat: nowSec - 600,
          exp: nowSec - 300, // expired 5 minutes ago
          iss: issuer,
        };
        if (audience) expiredPayload.aud = audience;
        const hdr = Buffer.from(
          JSON.stringify({ alg: "RS256", kid: _signingKid, typ: "JWT" }),
        ).toString("base64url");
        const pld = Buffer.from(JSON.stringify(expiredPayload)).toString("base64url");
        const sig = _signRaw(privateKey, `${hdr}.${pld}`);
        return `${hdr}.${pld}.${sig}`;
      }

      case "wrongTokenUse": {
        // Structurally valid and signed, but token_use claim is wrong.
        const { privateKey } = keyring.get(_signingKid);
        let b = new SignJWT({ ...claims, token_use: "INVALID_USE" })
          .setProtectedHeader({ alg: "RS256", kid: _signingKid })
          .setIssuedAt()
          .setIssuer(issuer)
          .setExpirationTime("10m");
        if (audience) b = b.setAudience(audience);
        return b.sign(privateKey);
      }

      case "missingTokenUse": {
        // Structurally valid, correctly signed, not expired — but no token_use claim.
        const { privateKey } = keyring.get(_signingKid);
        let b = new SignJWT({ ...claims })
          .setProtectedHeader({ alg: "RS256", kid: _signingKid })
          .setIssuedAt()
          .setIssuer(issuer)
          .setExpirationTime("10m");
        if (audience) b = b.setAudience(audience);
        return b.sign(privateKey);
      }

      default:
        throw new Error(`[keys] Unknown invalid token mode: ${mode}`);
    }
  }

  return {
    issuer,
    /** The kid currently used to sign new tokens. */
    get signingKid() {
      return _signingKid;
    },
    /** Live JWKS document — always reflects the current keyring. */
    get jwks() {
      return _buildJwks();
    },
    rotate,
    retireOldKeys,
    sign,
    signInvalid,
  };
}

module.exports = { createIssuer };
