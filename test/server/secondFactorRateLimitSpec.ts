/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import type { Request } from 'express'
import { clientKey, trustedProxies, trustedProxyHops } from '../../lib/secondFactorRateLimit'
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

    it('ignores X-Forwarded-For from a direct connection outside private networks', () => {
      expect(clientKey(requestFrom('198.51.100.1', '6.6.6.6'), 1)).to.equal('198.51.100.1')
      expect(clientKey(requestFrom('::ffff:198.51.100.1', '6.6.6.6'), 1)).to.equal('::ffff:198.51.100.1')
    })

    it('stops at the first proxy hop outside private networks', () => {
      expect(clientKey(requestFrom('10.0.0.1', '6.6.6.6, 198.51.100.1'), 2)).to.equal('198.51.100.1')
    })

    it('trusts public proxy addresses listed in JUICE_SHOP_TRUSTED_PROXIES', () => {
      const trusted = trustedProxies('198.51.100.10, 2001:db8::/32, 203.0.113.0/40, nonsense')
      expect(clientKey(requestFrom('198.51.100.10', '203.0.113.8'), 1, trusted)).to.equal('203.0.113.8')
      expect(clientKey(requestFrom('198.51.100.10', '203.0.113.9'), 1, trusted)).to.equal('203.0.113.9')
      expect(clientKey(requestFrom('2001:db8::5', '203.0.113.8'), 1, trusted)).to.equal('203.0.113.8')
      expect(clientKey(requestFrom('198.51.100.11', '203.0.113.8'), 1, trusted)).to.equal('198.51.100.11')
    })

    it('trusts public proxies listed as IPv4-mapped IPv6 addresses or ranges', () => {
      expect(clientKey(requestFrom('::ffff:198.51.100.10', '203.0.113.8'), 1, trustedProxies('::ffff:198.51.100.10'))).to.equal('203.0.113.8')
      expect(clientKey(requestFrom('::ffff:198.51.100.10', '203.0.113.9'), 1, trustedProxies('::ffff:198.51.100.0/120'))).to.equal('203.0.113.9')
      expect(clientKey(requestFrom('::ffff:198.51.100.10', '203.0.113.8'), 1, trustedProxies('198.51.100.10'))).to.equal('203.0.113.8')
      expect(clientKey(requestFrom('::ffff:198.51.100.11', '203.0.113.8'), 1, trustedProxies('::ffff:198.51.100.10'))).to.equal('::ffff:198.51.100.11')
    })

    it('trusts loopback and IPv4-mapped private proxy addresses', () => {
      expect(clientKey(requestFrom('::1', '203.0.113.9'), 1)).to.equal('203.0.113.9')
      expect(clientKey(requestFrom('::ffff:172.18.0.2', '203.0.113.9'), 1)).to.equal('203.0.113.9')
    })
  })
})
