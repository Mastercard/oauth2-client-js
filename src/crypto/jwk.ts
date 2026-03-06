/**
 * JWK Thumbprint (jkt) computation
 * https://tools.ietf.org/html/rfc7638
 */

import { base64urlEncode } from '#crypto/base64';
import { RuntimeEnvironment } from '#utils/runtime';

export async function computeJwkThumbprint(publicKey: CryptoKey): Promise<string> {
  const runtime = RuntimeEnvironment.detect();

  const jwk = await runtime.cryptoProvider.exportKey('jwk', publicKey);

  const canonicalJwk = getCanonicalJwk(jwk);

  const jsonString = JSON.stringify(canonicalJwk);

  const encoder = new TextEncoder();
  const data = encoder.encode(jsonString);

  const hashBuffer = await runtime.cryptoProvider.digest('SHA-256', data);

  return base64urlEncode(hashBuffer);
}

function getCanonicalJwk(jwk: JsonWebKey): Record<string, string> {
  const kty = jwk.kty;

  if (!kty) {
    throw new Error('JWK missing required "kty" parameter');
  }

  switch (kty) {
    case 'RSA':
      return getCanonicalRsaJwk(jwk);
    case 'EC':
      return getCanonicalEcJwk(jwk);
    default:
      throw new Error(`Unsupported key type for JWK thumbprint: ${kty}`);
  }
}

function getCanonicalRsaJwk(jwk: JsonWebKey): Record<string, string> {
  if (!jwk.e || !jwk.n) {
    throw new Error('RSA JWK missing required parameters (e, n)');
  }

  return {
    e: jwk.e,
    kty: 'RSA',
    n: jwk.n
  };
}

function getCanonicalEcJwk(jwk: JsonWebKey): Record<string, string> {
  if (!jwk.crv || !jwk.x || !jwk.y) {
    throw new Error('EC JWK missing required parameters (crv, x, y)');
  }

  return {
    crv: jwk.crv,
    kty: 'EC',
    x: jwk.x,
    y: jwk.y
  };
}
