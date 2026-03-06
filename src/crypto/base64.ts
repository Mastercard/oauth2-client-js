export function base64urlEncode(data: string | ArrayBuffer | Uint8Array): string {
  let base64: string;

  if (typeof data === 'string') {
    base64 = Buffer.from(data, 'utf8').toString('base64');
  } else {
    const uint8Array = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
    base64 = Buffer.from(uint8Array).toString('base64');
  }

  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
