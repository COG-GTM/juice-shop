/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import type { Request } from 'express'
import { clientKey, trustedProxyHops } from '../../lib/secondFactorRateLimit'
const expect = chai.expect

const requestFrom = (remoteAddress: string, forwardedFor?: string) => ({ socket: { remoteAddress }, headers: forwardedFor === undefined ? {} : { 'x-forwarded-for': forwardedFor } }) as unknown as Request

describe('secondFactorRateLimit', () => {
  describe('trustedProxyHops', () => {
    it('defaults to no trusted proxy', () => {
      expect(trustedProxyHops(undefined)).to.equal(0)
      expect(trustedProxyHops('')).to.equal(0)
      expect(trustedProxyHops('abc')).to.equal(0)
      expect(trustedProxyHops('-1')).to.equal(0)
      expect(trustedProxyHops('1.5')).to.equal(0)
    })

    it('accepts a positive number of hops', () => {
      expect(trustedProxyHops('2')).to.equal(2)
    })
  })

  describe('clientKey', () => {
    it('ignores X-Forwarded-For without trusted proxies', () => {
      expect(clientKey(requestFrom('10.0.0.1', '203.0.113.9'), 0)).to.equal('10.0.0.1')
    })

    it('uses the address appended by a single trusted proxy', () => {
      expect(clientKey(requestFrom('10.0.0.1', '6.6.6.6, 203.0.113.9'), 1)).to.equal('203.0.113.9')
    })

    it('walks back one entry per trusted proxy', () => {
      expect(clientKey(requestFrom('10.0.0.1', '6.6.6.6, 203.0.113.9, 10.0.0.2'), 2)).to.equal('203.0.113.9')
    })

    it('falls back to the leftmost entry when there are fewer entries than trusted hops', () => {
      expect(clientKey(requestFrom('10.0.0.1', '203.0.113.9'), 3)).to.equal('203.0.113.9')
      expect(clientKey(requestFrom('10.0.0.1'), 1)).to.equal('10.0.0.1')
    })
  })
})
