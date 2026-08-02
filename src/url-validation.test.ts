import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { validateFastmailUrl } from './url-validation.js';

describe('validateFastmailUrl (default policy)', () => {
  it('accepts api.fastmail.com over HTTPS', () => {
    const url = validateFastmailUrl('https://api.fastmail.com/jmap/api/', 'apiUrl');
    assert.equal(url.hostname, 'api.fastmail.com');
  });

  it('accepts www.fastmailusercontent.com over HTTPS', () => {
    const url = validateFastmailUrl('https://www.fastmailusercontent.com/jmap/download/x/y/z', 'downloadUrl');
    assert.equal(url.hostname, 'www.fastmailusercontent.com');
  });

  it('rejects HTTP even on allowed host', () => {
    assert.throws(
      () => validateFastmailUrl('http://api.fastmail.com/jmap/api/', 'baseUrl'),
      /must use HTTPS/,
    );
  });

  it('rejects non-allowlisted host', () => {
    assert.throws(
      () => validateFastmailUrl('https://attacker.example.com/jmap/api/', 'baseUrl'),
      /not in the Fastmail allowlist/,
    );
  });

  it('rejects subdomain of fastmail.com that is not on the explicit allowlist', () => {
    // www.fastmail.com is NOT in the allowlist — only api and the user-content host.
    assert.throws(
      () => validateFastmailUrl('https://www.fastmail.com/jmap/api/', 'baseUrl'),
      /not in the Fastmail allowlist/,
    );
  });

  it('accepts a regional api shard', () => {
    // Fastmail moved this account to the Philadelphia shard; session discovery
    // returns phl.api.fastmail.com and the exact-match allowlist rejected it.
    const url = validateFastmailUrl('https://phl.api.fastmail.com/jmap/api/', 'session.apiUrl');
    assert.equal(url.hostname, 'phl.api.fastmail.com');
  });

  it('accepts a regional user-content shard', () => {
    const url = validateFastmailUrl(
      'https://phl-www.fastmailusercontent.com/jmap/download/x/y/z',
      'downloadUrl',
    );
    assert.equal(url.hostname, 'phl-www.fastmailusercontent.com');
  });

  it('rejects a host that merely ends with the api hostname, no label boundary', () => {
    // 'evilapi.fastmail.com' ends with 'api.fastmail.com' but not with
    // '.api.fastmail.com' — the leading dot on the suffix is what stops this.
    assert.throws(
      () => validateFastmailUrl('https://evilapi.fastmail.com/jmap/api/', 'baseUrl'),
      /not in the Fastmail allowlist/,
    );
  });

  it('rejects an attacker domain that prefixes an allowlisted suffix', () => {
    assert.throws(
      () => validateFastmailUrl('https://phl.api.fastmail.com.attacker.com/', 'baseUrl'),
      /not in the Fastmail allowlist/,
    );
  });

  it('rejects host that ends with allowlisted domain (suffix-attack)', () => {
    // Confirms exact-match check, not endsWith.
    assert.throws(
      () => validateFastmailUrl('https://evilapi.fastmail.com.attacker.com/', 'baseUrl'),
      /not in the Fastmail allowlist/,
    );
  });

  it('rejects malformed URL', () => {
    assert.throws(
      () => validateFastmailUrl('not a url', 'baseUrl'),
      /not a valid URL/,
    );
  });

  it('rejects javascript: scheme', () => {
    assert.throws(
      () => validateFastmailUrl('javascript:fetch("https://attacker")', 'baseUrl'),
      /must use HTTPS/,
    );
  });

  it('rejects ftp: scheme', () => {
    assert.throws(
      () => validateFastmailUrl('ftp://api.fastmail.com/jmap/', 'baseUrl'),
      /must use HTTPS/,
    );
  });

  it('error message names the field for diagnostics', () => {
    try {
      validateFastmailUrl('https://attacker.example.com/', 'session.apiUrl');
      assert.fail('should have thrown');
    } catch (e) {
      assert.match((e as Error).message, /session\.apiUrl/);
    }
  });
});

describe('validateFastmailUrl (allowUnsafe=true)', () => {
  it('accepts arbitrary HTTPS host when opted in', () => {
    const url = validateFastmailUrl('https://jmap.self-hosted.example/jmap/api/', 'baseUrl', true);
    assert.equal(url.hostname, 'jmap.self-hosted.example');
  });

  it('still rejects HTTP even with opt-in', () => {
    assert.throws(
      () => validateFastmailUrl('http://jmap.self-hosted.example/jmap/api/', 'baseUrl', true),
      /must use HTTPS/,
    );
  });

  it('still rejects non-URL input', () => {
    assert.throws(
      () => validateFastmailUrl('garbage', 'baseUrl', true),
      /not a valid URL/,
    );
  });
});
