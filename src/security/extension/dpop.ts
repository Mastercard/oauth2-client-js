import { JWTSigner, JWTUtils } from '#crypto/jwt';
import type {
  DPoPKey,
  DPoPKeyProvider,
  JWTHeader,
  KeyPair,
  RuntimeEnvironment as RuntimeEnvironmentType
} from '#types';
import { RuntimeEnvironment } from '#utils/runtime';
import { getAlgorithmFromKey } from '#utils/crypto';
import { computeJwkThumbprint } from '#crypto/jwk';
import { base64urlEncode } from '#crypto/base64';

/**
 * Generates DPoP proof JWTs for OAuth2 token requests and resource server calls.
 * This class manages nonce state for authorization server nonce requirements.
 * See: <a href="https://datatracker.ietf.org/doc/html/rfc9449">RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession (DPoP)</a>
 */
export class DPoPProofGenerator {
  private jwtSigner = new JWTSigner();
  private nonce: string | null = null;

  constructor(
    private keyProvider: DPoPKeyProvider,
    private clockSkewTolerance: number = 0
  ) {}

  /**
   * Creates a DPoP proof token for the specified HTTP method and URL.
   * This token proves possession of the DPoP key pair and binds it to an access token.
   */
  async generateProof(
    httpMethod: string,
    url: string,
    dPoPKeyId: string,
    nonce?: string,
    accessToken?: string
  ): Promise<string> {
    const dPoPKey = this.keyProvider.getKey(dPoPKeyId).getKeyPair();
    const publicKey = dPoPKey.publicKey;
    const privateKey = dPoPKey.privateKey;

    const runtime = this.getRuntime();
    const jwk = await runtime.cryptoProvider.exportKey('jwk', publicKey);

    const jti = JWTUtils.generateJti();

    const iat = Math.floor(Date.now() / 1000);

    const payload: Record<string, string | number> = {
      jti,
      htm: httpMethod.toUpperCase(),
      htu: this.canonicalizeUrl(url),
      iat,
      exp: iat + 90 + this.clockSkewTolerance
    };

    if (accessToken) {
      payload.ath = await this.hashAccessToken(accessToken);
    }

    const nonceToUse = nonce ?? this.nonce?.toString();
    if (nonceToUse) payload.nonce = nonceToUse;

    const header: Partial<JWTHeader> = {
      typ: 'dpop+jwt',
      alg: getAlgorithmFromKey(privateKey),
      jwk: this.jwkForDPoP(jwk),
      kid: dPoPKeyId
    };

    return await this.jwtSigner.signJWT(payload, privateKey, header);
  }

  /**
   * Updates the nonce value received from the authorization server.
   * The nonce will be used in subsequent DPoP proof generation.
   */
  updateNonce(nonce: string): void {
    this.nonce = nonce;
  }

  /**
   * Canonicalize URL for htu claim: returns the HTTP URI of the request without query and fragment parts.
   * See: <a href="https://datatracker.ietf.org/doc/html/rfc9449#DPoP-Proof-Syntax">DPoP Proof JWT Syntax</a>
   */
  private canonicalizeUrl(url: string): string {
    try {
      const parsedUrl = new URL(url);
      const port =
        parsedUrl.port && parsedUrl.protocol === 'https:' && parsedUrl.port !== '443' ? `:${parsedUrl.port}` : '';
      return `${parsedUrl.protocol}//${parsedUrl.hostname}${port}${parsedUrl.pathname}`;
    } catch {
      throw new Error(`Invalid URL for DPoP htu claim: ${url}`);
    }
  }

  /**
   * Computes the `ath` claim value (access token hash).
   * See: <a href="https://datatracker.ietf.org/doc/html/rfc9449#section-4.2">DPoP Proof JWT Syntax</a>
   */
  private async hashAccessToken(accessToken: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(accessToken);
    const runtime = this.getRuntime();
    const hashBuffer = await runtime.cryptoProvider.digest('SHA-256', data);

    const hashArray = new Uint8Array(hashBuffer);
    return base64urlEncode(hashArray);
  }

  private jwkForDPoP(jwk: JsonWebKey): JsonWebKey {
    if (jwk.kty === 'EC') {
      if (!jwk.crv || !jwk.x || !jwk.y) {
        throw new Error('Invalid JWK: missing required properties for EC key');
      }
      return {
        kty: jwk.kty,
        crv: jwk.crv,
        x: jwk.x,
        y: jwk.y
      };
    } else if (jwk.kty === 'RSA') {
      if (!jwk.kty || !jwk.n || !jwk.e) {
        throw new Error('Invalid JWK: missing required properties');
      }
      return {
        kty: jwk.kty,
        n: jwk.n,
        e: jwk.e
      };
    } else {
      throw new Error(`Unsupported JWK (kty: ${jwk.kty})`);
    }
  }

  private getRuntime(): RuntimeEnvironmentType {
    return RuntimeEnvironment.detect();
  }
}

/**
 * Provides a static DPoP key pair.
 * The key identifier is the public key thumbprint.
 * This provider is suitable for scenarios where key rotation is not required.
 */
export class StaticDPoPKeyProvider implements DPoPKeyProvider {
  private readonly dpopKey: DPoPKey;
  private cachedThumbprint?: string;

  /**
   * Creates a new static DPoP key provider with the specified key pair.
   * The key identifier is automatically computed from the public key thumbprint.
   */
  constructor(
    private privateKey: CryptoKey,
    private publicKey: CryptoKey
  ) {
    const keyPair: KeyPair = { privateKey: this.privateKey, publicKey: this.publicKey };
    this.dpopKey = {
      getKeyPair: () => keyPair,
      getKeyId: async () => {
        if (!this.cachedThumbprint) {
          this.cachedThumbprint = await computeJwkThumbprint(publicKey);
        }
        return this.cachedThumbprint;
      }
    };
  }

  /** Gets the current key to be used for signing DPoP proofs. */
  getCurrentKey(): DPoPKey {
    return this.dpopKey;
  }

  /** Returns a key by `kid` (this provider always returns the same key pair). */
  getKey(_kid: string): DPoPKey {
    return this.dpopKey;
  }
}

/** Options for token refresh behavior during DPoP error handling. */
export interface DPoPRefreshOptions {
  isDPoPError: boolean;
  isDPoPRequired: boolean;
  dPoPKeyId: string | undefined;
}
