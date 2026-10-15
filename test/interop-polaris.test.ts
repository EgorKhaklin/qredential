import { describe, it, expect } from 'vitest'
import { verify } from '../src/index.js'
import { utf8 } from '../src/bytes.js'
import fixture from './polaris-wallet-copy.json'
import type { Jwk, TrustList } from '../src/types.js'

/**
 * Differential testing against an implementation that is not JavaScript (issue #23).
 *
 * test/polaris-wallet-copy.json is an SD-JWT VC issued by Polaris ID, a Python implementation, so
 * none of the platform primitives this library shares with @sd-jwt/core are shared here: the
 * base64url of each disclosure, the UTF-8 bytes that get hashed, and the JSON text are all produced
 * by Python's base64 and json modules.
 *
 * Provenance is in the fixture's `source` field. To regenerate it: export the Polaris commit named
 * there, put polaris_web on the path, create a throwaway ES256 key, and call
 * `wallet_copy.build_copy(key, issuer, claims, holder_jwk, iat, exp, status_index, status_uri)`
 * with the claims in `expectedClaims`. The issuer key is thrown away; only its public half is kept.
 *
 * What the claims are chosen to catch: a non-ASCII value (accented Latin, CJK, an astral emoji),
 * characters that JSON must escape (quote, backslash, tab, newline) and a U+2028 line separator,
 * which JSON text may carry raw. Polaris writes them as raw UTF-8, not \uXXXX escapes.
 * statusListTokenWithIss is the same Polaris token re-signed with an iss claim added (see below).
 * Not covered: array-element disclosures, which Polaris does not issue.
 */

const issuerJwk = fixture.issuerPublicJwk as Jwk
const trust: TrustList = {
  issuers: { [fixture.issuer]: { keys: [{ kid: 'polaris-fixture', alg: 'ES256', jwk: issuerJwk }] } },
}

// The fixture was issued in the past on purpose; it must not rot, so check it as of its own iat.
const AT = 1767225600 // 2026-01-01T00:00:00Z

async function run(credential: string, status: string = fixture.statusListTokenWithIss) {
  return verify(credential, { trust, acceptWithoutHolderProof: true, now: AT, status })
}

describe('a Polaris ID credential, our verifier', () => {
  // Polaris signs its status list token without an \`iss\` claim, which draft-ietf-oauth-status-list
  // (-15) does not require. This library requires it to bind the list to the issuer, so it refuses
  // the token exactly as Polaris emits it. The tests below use the same token with \`iss\` added and
  // re-signed (statusListTokenWithIss); this one is the as-issued token and is expected to fail until
  // the two sides settle which is right.
  it('verifies with the status list token exactly as Polaris issues it', async () => {
    const result = await run(fixture.credential, fixture.statusListToken)
    expect(result).toMatchObject({ ok: true })
  })

  it('verifies, and every claim equals what the Python issuer put in, byte for byte', async () => {
    const result = await run(fixture.credential)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.withheld).toBe(0)
    for (const [name, expected] of Object.entries(fixture.expectedClaims)) {
      const got = result.claims[name]
      expect(typeof got).toBe(typeof expected)
      if (typeof expected === 'string') {
        expect(Array.from(utf8(got as string))).toEqual(Array.from(utf8(expected)))
      } else {
        expect(got).toBe(expected)
      }
    }
  })
})
