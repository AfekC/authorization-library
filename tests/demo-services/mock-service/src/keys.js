import { generateKeyPair, exportJWK, SignJWT } from "jose";
import crypto from "node:crypto";

/**
 * One Ed25519 (EdDSA) keypair for the Auth Service (user JWTs) and one for the
 * SSO provider (service tokens). Each exposes a JWKS; both libraries verify
 * against them. EdDSA is the only algorithm in the token path.
 *
 * Key rotation (G13):
 *   issuer.rotate()          â€” Generate a new keypair, publish old+new in JWKS,
 *                              and start signing with the new kid. Returns the new kid.
 *   issuer.retireOldKeys()   â€” Drop all keys except the current signing key from the
 *                              JWKS (call after the overlap window has elapsed).
 *   issuer.signingKid        â€” The kid currently used to sign new tokens (getter).
 *   issuer.jwks              â€” Live JWKS document (getter, always current).
 *
 * Invalid-token minting (G6):
 *   issuer.signInvalid(claims, opts)
 *                            â€” Mint a token that is deliberately broken. opts.mode:
 *     "expired"          â€” iat and exp both in the past (expired 5 min ago),
 *                          signed with the real private key so only exp is wrong.
 *     "wrongSignature"   â€” signed with a throwaway key not in the JWKS.
 *     "wrongTokenUse"    â€” valid token but token_use = "INVALID_USE".
 *     "missingTokenUse"  â€” correctly signed, non-expired token, no token_use claim.
 *     "missingClaims"    â€” omits iss/aud/exp; bare header+payload, bogus signature.
 *     "malformed"        â€” returns the literal string "not.a.jwt".
 */
async function createIssuer(issuer, initialKid, alg = "EdDSA") {
  // All active keypairs: kid -> { privateKey, publicJwk }
  const keyring = new Map();

  async function _generateKey(kid) {
    // jose v6 returns non-extractable WebCrypto CryptoKeys by default; request
    // extractable keys so the private key bridges cleanly to a Node KeyObject in
    // _signRaw (the raw "expired" signing path) and the public key exports to JWK.
    // alg is "EdDSA" (Ed25519/OKP) for both the Auth Service user tokens and the
    // SSO service tokens — the only algorithm in the token path.
    const { publicKey, privateKey } = await generateKeyPair(alg, { extractable: true });
    const jwk = await exportJWK(publicKey);
    jwk.kid = kid;
    jwk.use = "sig";
    jwk.alg = alg;
    keyring.set(kid, { privateKey, publicJwk: jwk });
  }

  await _generateKey(initialKid);
  let _signingKid = initialKid;

  // Build the JWKS document from all keys currently in the keyring.
  function _buildJwks() {
    return { keys: Array.from(keyring.values()).map((e) => e.publicJwk) };
  }

  // Sign `data` (ASCII string "header.payload") with Ed25519 using Node crypto.
  // Returns base64url-encoded signature. Used only for the "expired" path where
  // jose's SignJWT enforces a future exp and would reject a backdated one.
  function _signRaw(privateKey, data) {
    // jose v6 gives a WebCrypto CryptoKey; Node's crypto.sign needs a KeyObject.
    const keyObject = crypto.KeyObject.from(privateKey);
    // Ed25519 signs with no pre-hash and no padding (algorithm omitted/null).
    const sig = crypto.sign(null, Buffer.from(data), keyObject);
    return sig.toString("base64url");
  }

  // â”€â”€ Public API â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
      .setProtectedHeader({ alg, kid: _signingKid })
      .setIssuedAt()
      .setIssuer(issuer)
      .setExpirationTime(expiresIn);
    if (audience) b = b.setAudience(audience);
    return b.sign(privateKey);
  }

  /**
   * Mint a deliberately broken token for adverse-condition / G6 testing.
   * @param {object} claims  Base payload claims (e.g. { userId, roleId }).
   * @param {{ mode?: string, audience?: string }} opts
   * @returns {Promise<string>} The broken JWT (or literal "not.a.jwt").
   */
  async function signInvalid(claims = {}, { mode = "expired", audience } = {}) {
    switch (mode) {
      case "malformed":
        return "not.a.jwt";

      case "missingClaims": {
        // No iss, aud, or exp. Signature is structurally present but bogus.
        const hdr = Buffer.from(JSON.stringify({ alg, typ: "JWT" })).toString("base64url");
        const pld = Buffer.from(JSON.stringify(claims)).toString("base64url");
        return `${hdr}.${pld}.invalidsignature`;
      }

      case "wrongSignature": {
        // Signed with a throwaway key that is NOT in the JWKS.
        const { privateKey: throwaway } = await generateKeyPair(alg);
        let b = new SignJWT({ ...claims })
          .setProtectedHeader({ alg, kid: _signingKid })
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
          JSON.stringify({ alg, kid: _signingKid, typ: "JWT" }),
        ).toString("base64url");
        const pld = Buffer.from(JSON.stringify(expiredPayload)).toString("base64url");
        const sig = _signRaw(privateKey, `${hdr}.${pld}`);
        return `${hdr}.${pld}.${sig}`;
      }

      case "wrongTokenUse": {
        // Structurally valid and signed, but token_use claim is wrong.
        const { privateKey } = keyring.get(_signingKid);
        let b = new SignJWT({ ...claims, token_use: "INVALID_USE" })
          .setProtectedHeader({ alg, kid: _signingKid })
          .setIssuedAt()
          .setIssuer(issuer)
          .setExpirationTime("10m");
        if (audience) b = b.setAudience(audience);
        return b.sign(privateKey);
      }

      case "missingTokenUse": {
        // Structurally valid, correctly signed, not expired â€” but no token_use claim.
        const { privateKey } = keyring.get(_signingKid);
        let b = new SignJWT({ ...claims })
          .setProtectedHeader({ alg, kid: _signingKid })
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
    /** Live JWKS document â€” always reflects the current keyring. */
    get jwks() {
      return _buildJwks();
    },
    rotate,
    retireOldKeys,
    sign,
    signInvalid,
  };
}

export { createIssuer };

