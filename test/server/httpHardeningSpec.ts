/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import config from 'config'
import { corsAllowedOrigins, corsOptions, loadCookieParserSecret } from '../../lib/httpHardening'

const expect = chai.expect

describe('httpHardening', () => {
  describe('loadCookieParserSecret', () => {
    it('uses COOKIE_PARSER_SECRET from the environment', () => {
      expect(loadCookieParserSecret({ COOKIE_PARSER_SECRET: 's3cr3t' })).to.equal('s3cr3t')
    })

    it('falls back to a random secret instead of a hardcoded one', () => {
      const first = loadCookieParserSecret({})
      const second = loadCookieParserSecret({ COOKIE_PARSER_SECRET: ' ' })
      expect(first).to.match(/^[0-9a-f]{64}$/)
      expect(second).to.match(/^[0-9a-f]{64}$/)
      expect(first).to.not.equal(second)
    })
  })

  describe('corsAllowedOrigins', () => {
    it('defaults to the configured base URL and the Angular dev server', () => {
      expect(corsAllowedOrigins({})).to.deep.equal([config.get<string>('server.baseUrl'), 'http://localhost:4200', 'http://127.0.0.1:4200'])
    })

    it('reads a comma-separated list from CORS_ALLOWED_ORIGINS', () => {
      expect(corsAllowedOrigins({ CORS_ALLOWED_ORIGINS: ' https://a.example/ , ,https://b.example' })).to.deep.equal(['https://a.example', 'https://b.example'])
    })

    it('ignores a wildcard entry', () => {
      expect(corsAllowedOrigins({ CORS_ALLOWED_ORIGINS: '*,https://a.example' })).to.deep.equal(['https://a.example'])
    })
  })

  describe('corsOptions', () => {
    const decide = (origin: string | undefined) => {
      const callback = sinon.spy()
      const originFn = corsOptions(['https://shop.example']).origin as (origin: string | undefined, cb: (err: Error | null, allow?: boolean) => void) => void
      originFn(origin, callback)
      return callback.firstCall.args[1]
    }

    it('allows listed origins', () => {
      expect(decide('https://shop.example')).to.equal(true)
    })

    it('rejects unlisted origins', () => {
      expect(decide('https://attacker.example')).to.equal(false)
      expect(decide('null')).to.equal(false)
    })

    it('sends no CORS header for requests without Origin', () => {
      expect(decide(undefined)).to.equal(false)
    })
  })
})
