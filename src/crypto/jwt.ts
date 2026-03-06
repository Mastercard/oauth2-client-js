import { base64urlEncode } from '#crypto/base64';
import type { JWTAlgorithm, JWTHeader, JWTPayload } from '#types';
import { RuntimeEnvironment } from '#utils/runtime';
import { getAlgorithmFromKey } from '#utils/crypto';

export class JWTUtils {
  static generateJti(): string {
    const runtime = RuntimeEnvironment.detect();
    const array = new Uint8Array(12); // 96 bits
    runtime.cryptoProvider.getRandomValues(array);

    return base64urlEncode(array);
  }
}

export class JWTSigner {
  async signJWT(payload: JWTPayload, privateKey: CryptoKey, header: Partial<JWTHeader> = {}): Promise<string> {
    const algorithm = getAlgorithmFromKey(privateKey);

    const jwtHeader: JWTHeader = {
      alg: algorithm,
      typ: 'JWT',
      ...header
    };

    const encodedHeader = base64urlEncode(JSON.stringify(jwtHeader));
    const encodedPayload = base64urlEncode(JSON.stringify(payload));
    const signingInput = `${encodedHeader}.${encodedPayload}`;

    const signature = await this.sign(signingInput, privateKey, algorithm);
    const encodedSignature = base64urlEncode(signature);

    return `${signingInput}.${encodedSignature}`;
  }

  private async sign(data: string, privateKey: CryptoKey, algorithm: JWTAlgorithm): Promise<ArrayBuffer> {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);

    const cryptoAlgorithm = this.getCryptoAlgorithm(algorithm);
    const runtime = this.getRuntime();
    return await runtime.cryptoProvider.sign(cryptoAlgorithm, privateKey, dataBuffer);
  }

  private getCryptoAlgorithm(algorithm: JWTAlgorithm): EcdsaParams | RsaHashedImportParams | RsaPssParams {
    switch (algorithm) {
      case 'ES256':
        return { name: 'ECDSA', hash: { name: 'SHA-256' } } as EcdsaParams;
      case 'PS256':
        return { name: 'RSA-PSS', hash: { name: 'SHA-256' }, saltLength: 32 } as RsaPssParams;
      default:
        throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  private getRuntime() {
    return RuntimeEnvironment.detect();
  }
}
