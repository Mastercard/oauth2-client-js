import type { CryptoProvider, RuntimeEnvironment as RuntimeEnvironmentType } from '#types';
import { WebCryptoProvider } from '#crypto/crypto-provider';

/**
 * Detects and provides runtime environment capabilities including `Web Crypto API`.
 * Supports custom configuration for non-standard environments via {@link RuntimeEnvironment.configure}.
 */
export class RuntimeEnvironment {
  private static instance: RuntimeEnvironmentType | null = null;
  private static customInstance: RuntimeEnvironmentType | null = null;

  /**
   * Set a custom runtime environment
   */
  static configure(runtime: RuntimeEnvironmentType): void {
    this.customInstance = runtime;
  }

  /**
   * Reset to auto-detected runtime environment
   */
  static reset(): void {
    this.customInstance = null;
    this.instance = null;
  }

  /** Detects and returns the current runtime environment, using cached or custom instance if available. */
  static detect(): RuntimeEnvironmentType {
    if (this.customInstance) {
      return this.customInstance;
    }

    if (this.instance) {
      return this.instance;
    }

    const crypto = globalThis.crypto;
    if (!crypto || typeof crypto.subtle === 'undefined') {
      throw new Error(
        'Web Crypto API is not available in this environment. Configure a custom runtime via RuntimeEnvironment.configure().'
      );
    }

    const cryptoProvider: CryptoProvider = new WebCryptoProvider(crypto);

    const env: RuntimeEnvironmentType = {
      crypto: crypto,
      cryptoProvider: cryptoProvider,
      osName: 'unknown',
      osVersion: 'unknown'
    };

    try {
      const os = require('os');
      env.osName = os.platform();
      env.osVersion = os.release();
    } catch {
      // os module not available
    }

    this.instance = env;
    return env;
  }
}
