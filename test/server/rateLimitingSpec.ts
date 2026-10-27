/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request } from 'express'
import chai from 'chai'

import * as rateLimiting from '../../lib/rateLimiting'

const expect = chai.expect

const requestWithBody = (body: any) => ({ body }) as unknown as Request

describe('rateLimiting', () => {
  describe('trustedProxyHops', () => {
    it('does not trust any proxy by default', () => {
      expect(rateLimiting.trustedProxyHops(undefined)).to.equal(false)
      expect(rateLimiting.trustedProxyHops('')).to.equal(false)
    })

    it('trusts the configured number of proxy hops', () => {
      expect(rateLimiting.trustedProxyHops('1')).to.equal(1)
      expect(rateLimiting.trustedProxyHops('2')).to.equal(2)
    })

    it('rejects values that would trust every hop or are invalid', () => {
      expect(rateLimiting.trustedProxyHops('true')).to.equal(false)
      expect(rateLimiting.trustedProxyHops('0')).to.equal(false)
      expect(rateLimiting.trustedProxyHops('-1')).to.equal(false)
      expect(rateLimiting.trustedProxyHops('1.5')).to.equal(false)
      expect(rateLimiting.trustedProxyHops('loopback')).to.equal(false)
    })
  })

  describe('emailOf', () => {
    it('normalizes the targeted email address', () => {
      expect(rateLimiting.emailOf(requestWithBody({ email: ' Jim@Juice-sh.op ' }))).to.equal('jim@juice-sh.op')
    })

    it('puts all non-string emails into one shared bucket', () => {
      expect(rateLimiting.emailOf(requestWithBody({ email: ['a@b.c'] }))).to.equal('<non-string>')
      expect(rateLimiting.emailOf(requestWithBody({ email: { $like: '%' } }))).to.equal('<non-string>')
      expect(rateLimiting.emailOf(requestWithBody({ email: 1 }))).to.equal('<non-string>')
    })

    it('returns undefined without a usable email', () => {
      expect(rateLimiting.emailOf(requestWithBody({}))).to.equal(undefined)
      expect(rateLimiting.emailOf(requestWithBody({ email: '  ' }))).to.equal(undefined)
      expect(rateLimiting.emailOf(requestWithBody(undefined))).to.equal(undefined)
    })
  })
})
