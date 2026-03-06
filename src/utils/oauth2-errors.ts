export function isDPoPNonceError(status: number, headers: Record<string, string>, body?: string): boolean {
  if (status !== 400 && status !== 401) {
    return false;
  }
  try {
    if (body) {
      const errorData = JSON.parse(body);
      if (errorData?.error === 'use_dpop_nonce') {
        return true;
      }
    }
  } catch {
    // Response body is not valid JSON
  }
  return headers?.['www-authenticate']?.includes('use_dpop_nonce') ?? false;
}
