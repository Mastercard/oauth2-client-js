import type { CryptoProvider } from '#types';

/**
 * Default Web Crypto API implementation
 */
export class WebCryptoProvider implements CryptoProvider {
  constructor(private crypto: Crypto) {}

  async exportKey(format: 'jwk', key: CryptoKey): Promise<JsonWebKey> {
    return await this.crypto.subtle.exportKey(format, key);
  }

  async digest(algorithm: 'SHA-256', data: BufferSource): Promise<ArrayBuffer> {
    return await this.crypto.subtle.digest(algorithm, data);
  }

  async sign(
    algorithm: EcdsaParams | RsaHashedImportParams | RsaPssParams,
    key: CryptoKey,
    data: BufferSource
  ): Promise<ArrayBuffer> {
    return await this.crypto.subtle.sign(algorithm, key, data);
  }

  getRandomValues<T extends ArrayBufferView>(array: T): T {
    return this.crypto.getRandomValues(array as ArrayBufferView) as T;
  }
}
