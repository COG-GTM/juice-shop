/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import type { Request } from 'express'
import * as security from '../../lib/insecurity'
import { accountKey, clientAddress, trustedProxyHops } from '../../lib/secondFactorRateLimit'
const expect = chai.expect

const requestFrom = (remoteAddress: string, forwardedFor?: string, body: any = {}) => ({
  socket: { remoteAddress },
  headers: forwardedFor === undefined ? {} : { 'x-forwarded-for': forwardedFor },
  body
}) as unknown as Request

describe('secondFactorRateLimit', () => {
  describe('trustedProxyHops', () => {
    it('defaults to no trusted proxy', () => {
      expect(trustedProxyHops(undefined)).to.equal(0)
    })

    it('accepts non-negative integers only', () => {
      expect(trustedProxyHops('2')).to.equal(2)
      expect(trustedProxyHops('-1')).to.equal(0)
      expect(trustedProxyHops('true')).to.equal(0)
      expect(trustedProxyHops('1.5')).to.equal(0)
    })
  })

  describe('clientAddress', () => {
    it('ignores X-Forwarded-For when no proxy is trusted', () => {
      expect(clientAddress(requestFrom('203.0.113.7', '10.0.0.1'), 0)).to.equal('203.0.113.7')
    })

    it('only honours the X-Forwarded-For entries added by trusted proxies', () => {
      expect(clientAddress(requestFrom('10.0.0.2', '1.1.1.1, 198.51.100.4'), 1)).to.equal('198.51.100.4')
      expect(clientAddress(requestFrom('10.0.0.2', '1.1.1.1, 198.51.100.4, 10.0.0.3'), 2)).to.equal('198.51.100.4')
    })

    it('falls back to the leftmost address when the chain is shorter than the hop count', () => {
      expect(clientAddress(requestFrom('10.0.0.2', '198.51.100.4'), 3)).to.equal('198.51.100.4')
      expect(clientAddress(requestFrom('10.0.0.2'), 1)).to.equal('10.0.0.2')
    })
  })

  describe('accountKey', () => {
    it('is derived from the user id of a valid second factor token', () => {
      const tmpToken = security.authorize({ userId: 42, expiresAt: security.secondFactorTokenExpiry(), type: 'password_valid_needs_second_factor_token' })
      expect(accountKey(requestFrom('127.0.0.1', undefined, { tmpToken }))).to.equal('2fa-user:42')
    })

    it('is undefined for forged or missing tokens', () => {
      const encode = (part: object) => Buffer.from(JSON.stringify(part)).toString('base64url')
      const forged = `${encode({ alg: 'none' })}.${encode({ userId: 42, expiresAt: security.secondFactorTokenExpiry(), type: 'password_valid_needs_second_factor_token' })}.`
      expect(accountKey(requestFrom('127.0.0.1', undefined, { tmpToken: forged }))).to.equal(undefined)
      expect(accountKey(requestFrom('127.0.0.1'))).to.equal(undefined)
    })
  })
})
