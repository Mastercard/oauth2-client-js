/**
 * Check if a URL is an absolute HTTPS URL (case-insensitive scheme check).
 */
export function isAbsoluteHttpsURL(url: string): boolean {
  return url.toLowerCase().startsWith('https://');
}

/**
 * Build a full URL from base and relative path
 */
export function buildFullUrl(base: string | undefined, path: string): string {
  if (isAbsoluteHttpsURL(path)) {
    return new URL(path).href;
  }
  if (!base) {
    return path;
  }
  const normalizedBase = base.endsWith('/') ? base : base + '/';
  return new URL(path.replace(/^\//, ''), normalizedBase).href;
}
