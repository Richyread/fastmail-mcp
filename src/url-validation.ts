// Validates URLs that will receive the bearer token. Restricts to approved
// Fastmail origins by default, with an explicit opt-out for self-hosted JMAP.

const FASTMAIL_ALLOWED_HOSTS: ReadonlySet<string> = new Set([
  'api.fastmail.com',
  'www.fastmailusercontent.com',
]);

// Fastmail shards accounts onto regional hosts and returns those from session
// discovery: an account on the Philadelphia shard is handed
// `phl.api.fastmail.com` and `phl-www.fastmailusercontent.com` rather than the
// two bare hosts above. Both are legitimate Fastmail endpoints, so the
// allowlist matches by suffix as well as exactly.
//
// Every suffix starts with a dot, which anchors the match at a label boundary.
// 'evilapi.fastmail.com' does not end with '.api.fastmail.com', and neither
// does 'api.fastmail.com.attacker.com' — the suffix-attack cases stay rejected.
// Only the api host gains subdomains, not the whole of fastmail.com, so
// 'www.fastmail.com' remains off the list.
const FASTMAIL_ALLOWED_HOST_SUFFIXES: readonly string[] = [
  '.api.fastmail.com',
  '.fastmailusercontent.com',
];

function isAllowedFastmailHost(hostname: string): boolean {
  if (FASTMAIL_ALLOWED_HOSTS.has(hostname)) return true;
  return FASTMAIL_ALLOWED_HOST_SUFFIXES.some((suffix) => hostname.endsWith(suffix));
}

/**
 * Validate that a URL is acceptable for sending the bearer token to.
 *
 * Default policy:
 *   - Must be HTTPS.
 *   - Hostname must be in FASTMAIL_ALLOWED_HOSTS, or a regional shard of one
 *     (see FASTMAIL_ALLOWED_HOST_SUFFIXES).
 *
 * When `allowUnsafe=true` (e.g. user opted in via FASTMAIL_ALLOW_UNSAFE_BASE_URL
 * for a self-hosted JMAP server):
 *   - Must still be HTTPS (plain HTTP is never allowed; the token would be sent
 *     in cleartext).
 *   - Any hostname is accepted.
 *
 * Throws on rejection; returns the parsed URL on success.
 */
export function validateFastmailUrl(input: string, fieldName: string, allowUnsafe = false): URL {
  let parsed: URL;
  try {
    parsed = new URL(input);
  } catch {
    throw new Error(`${fieldName} is not a valid URL`);
  }
  if (parsed.protocol !== 'https:') {
    throw new Error(
      `${fieldName} must use HTTPS (got: ${parsed.protocol}). ` +
      `Plain HTTP is rejected because the bearer token would be sent in cleartext.`,
    );
  }
  if (!allowUnsafe && !isAllowedFastmailHost(parsed.hostname)) {
    throw new Error(
      `${fieldName} host '${parsed.hostname}' is not in the Fastmail allowlist. ` +
      `Set FASTMAIL_ALLOW_UNSAFE_BASE_URL=true to opt in for self-hosted JMAP servers.`,
    );
  }
  return parsed;
}

export const FASTMAIL_ALLOWED_HOSTS_FOR_TEST = FASTMAIL_ALLOWED_HOSTS;
