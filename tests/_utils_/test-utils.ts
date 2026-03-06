import { readFileSync } from 'fs';
import * as forge from 'node-forge';
import { join } from 'path';

interface P12KeyInfo {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

/**
 * Load and parse PKCS#12 file using node-forge
 */
export async function loadP12File(filePath: string, alias: string, password: string): Promise<P12KeyInfo> {
  if (typeof process === 'undefined') {
    throw new Error('P12 loading is only supported in Node.js environment for tests');
  }

  const p12Content = readFileSync(join(process.cwd(), filePath), 'binary');
  const p12Asn1 = forge.asn1.fromDer(p12Content, false);
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password);

  const keyBags = p12.getBags({
    friendlyName: alias,
    bagType: forge.pki.oids.pkcs8ShroudedKeyBag
  });

  let privateKeyPem: string | null = null;
  let certificate: forge.pki.Certificate | null = null;

  if (keyBags.friendlyName && keyBags.friendlyName.length > 0) {
    const keyObj = keyBags.friendlyName[0];
    if (keyObj && keyObj.key) {
      const privateKeyInfo = forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(keyObj.key));
      privateKeyPem = forge.pki.privateKeyInfoToPem(privateKeyInfo);
    }
  }

  const certBags = p12.getBags({
    bagType: forge.pki.oids.certBag
  });

  const certBagTypeKey = forge.pki.oids.certBag as string;
  const certBags2 = certBags[certBagTypeKey];
  if (certBags2 && certBags2.length > 0) {
    const certObj = certBags2[0];
    if (certObj && certObj.cert) {
      certificate = certObj.cert;
    }
  }

  const privateKey = await importPEMPrivateKey(privateKeyPem);

  let publicKey: CryptoKey;
  if (certificate) {
    const publicKeyPem = forge.pki.publicKeyToPem(certificate.publicKey);
    publicKey = await importPEMPublicKey(publicKeyPem);
  }

  return {
    privateKey,
    publicKey
  };
}

async function importPEMPrivateKey(pemKey: string): Promise<CryptoKey> {
  try {
    const keyData = pemToBinary(pemKey);

    return await crypto.subtle.importKey(
      'pkcs8',
      keyData,
      {
        name: 'RSA-PSS',
        hash: 'SHA-256'
      },
      true,
      ['sign']
    );
  } catch (error) {
    console.error(`Failed to import private key: ${error}`);
    throw error;
  }
}

async function importPEMPublicKey(pemKey: string): Promise<CryptoKey> {
  try {
    const keyData = pemToBinary(pemKey);

    return await crypto.subtle.importKey(
      'spki',
      keyData,
      {
        name: 'RSA-PSS',
        hash: 'SHA-256'
      },
      true,
      ['verify']
    );
  } catch (error) {
    console.error(`Failed to import public key: ${error}`);
    throw error;
  }
}

function pemToBinary(pem: string): ArrayBuffer {
  const base64 = pem
    .replace(/-----BEGIN.*-----/g, '')
    .replace(/-----END.*-----/g, '')
    .replace(/\s/g, '');

  const buffer = Buffer.from(base64, 'base64');
  return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
}
