import type { JWTAlgorithm } from '#types';

/**
 * Get JWT algorithm from CryptoKey
 * Determines the appropriate JWT algorithm based on the key's cryptographic properties
 *
 * @param key - CryptoKey to inspect
 * @returns The corresponding JWT algorithm identifier
 * @throws Error if the key algorithm or curve/hash is unsupported
 */
export function getAlgorithmFromKey(key: CryptoKey): JWTAlgorithm {
  const algorithm = key.algorithm;

  if (algorithm.name === 'ECDSA') {
    const namedCurve = (algorithm as EcKeyAlgorithm).namedCurve;
    switch (namedCurve) {
      case 'P-256':
        return 'ES256';
      default:
        throw new Error(`Unsupported ECDSA curve: ${namedCurve}`);
    }
  }

  if (algorithm.name === 'RSA-PSS') {
    const hashAlg = (algorithm as RsaHashedKeyAlgorithm).hash;
    const hashName = hashAlg.name;
    switch (hashName) {
      case 'SHA-256':
        return 'PS256';
      default:
        throw new Error(`Unsupported RSA-PSS hash: ${hashName}`);
    }
  }

  throw new Error(`Unsupported key algorithm: ${algorithm.name}`);
}

/**
 * Validates that a cryptographic key meets FAPI 2.0 minimum length requirements.
 * Per FAPI 2.0 spec section 5.4 (Cryptography and secrets):
 * - RSA keys shall have a minimum length of 2048 bits
 * - Elliptic curve keys shall have a minimum length of 224 bits
 *
 * See: https://openid.bitbucket.io/fapi/fapi-security-profile-2_0.html#name-cryptography-and-secrets
 */
export function validateKeyFAPI2(key: CryptoKey, context: string): void {
  const algorithm = key.algorithm;

  if (algorithm.name === 'RSA-PSS' || algorithm.name === 'RSASSA-PKCS1-v1_5') {
    const rsaAlgorithm = algorithm as RsaHashedKeyAlgorithm;
    const modulusLength = rsaAlgorithm.modulusLength;

    if (modulusLength < 2048) {
      throw new Error(
        `FAPI 2.0 requires RSA keys to have a minimum length of 2048 bits for ${context}, but key length was: ${modulusLength} bits`
      );
    }
  } else if (algorithm.name === 'ECDSA') {
    const ecAlgorithm = algorithm as EcKeyAlgorithm;
    const namedCurve = ecAlgorithm.namedCurve;

    // Map named curves to their bit lengths
    const curveLength = getEcCurveLength(namedCurve);

    if (curveLength < 224) {
      throw new Error(
        `FAPI 2.0 requires Elliptic Curve keys to have a minimum length of 224 bits for ${context}, but curve ${namedCurve} has ${curveLength} bits`
      );
    }
  } else {
    throw new Error(`Unsupported key algorithm for ${context}: ${algorithm.name}`);
  }
}

/**
 * Maps EC named curves to their bit lengths
 * @param namedCurve - The named curve identifier (e.g., 'P-256')
 * @returns The bit length of the curve
 * @throws Error if the curve is not recognized
 */
function getEcCurveLength(namedCurve: string): number {
  switch (namedCurve) {
    case 'P-224':
      return 224;
    case 'P-256':
      return 256;
    case 'P-384':
      return 384;
    case 'P-521':
      return 521;
    default:
      throw new Error(`Unsupported or unrecognized elliptic curve: ${namedCurve}`);
  }
}
