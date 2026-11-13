/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import config from 'config'
import { corsAllowedOrigins, corsOptions } from '../../lib/corsOptions'
const expect = chai.expect

function isAllowed (allowedOrigins: string[], origin: string | undefined): boolean {
  let result = false
  const originOption = corsOptions(allowedOrigins).origin as (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => void
  originOption(origin, (_err, allow) => { result = allow === true })
  return result
}

describe('corsOptions', () => {
  it('defaults to the configured baseUrl and the local Angular dev server', () => {
    expect(corsAllowedOrigins({})).to.deep.equal([config.get<string>('server.baseUrl'), 'http://localhost:4200', 'http://127.0.0.1:4200'])
  })

  it('reads a comma-separated allowlist from CORS_ALLOWED_ORIGINS', () => {
    expect(corsAllowedOrigins({ CORS_ALLOWED_ORIGINS: ' https://shop.example/ , https://admin.example ' })).to.deep.equal(['https://shop.example', 'https://admin.example'])
  })

  it('ignores wildcard and empty entries in CORS_ALLOWED_ORIGINS', () => {
    expect(corsAllowedOrigins({ CORS_ALLOWED_ORIGINS: '*,,https://shop.example' })).to.deep.equal(['https://shop.example'])
  })

  it('allows only allowlisted origins', () => {
    expect(isAllowed(['https://shop.example'], 'https://shop.example')).to.equal(true)
    expect(isAllowed(['https://shop.example'], 'https://attacker.example')).to.equal(false)
    expect(isAllowed(['https://shop.example'], 'null')).to.equal(false)
  })

  it('sends no CORS headers for requests without an Origin header', () => {
    expect(isAllowed(['https://shop.example'], undefined)).to.equal(false)
  })
})
