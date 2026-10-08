/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request } from 'express'
import chai from 'chai'

import * as security from '../../lib/insecurity'
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

    it('returns undefined without a usable email', () => {
      expect(rateLimiting.emailOf(requestWithBody({}))).to.equal(undefined)
      expect(rateLimiting.emailOf(requestWithBody({ email: '  ' }))).to.equal(undefined)
      expect(rateLimiting.emailOf(requestWithBody({ email: ['a@b.c'] }))).to.equal(undefined)
      expect(rateLimiting.emailOf(requestWithBody(undefined))).to.equal(undefined)
    })
  })

  describe('secondFactorUserOf', () => {
    it('returns the user id of a validly signed temporary 2FA token', () => {
      const tmpToken = security.authorize({ userId: 10, type: 'password_valid_needs_second_factor_token' })
      expect(rateLimiting.secondFactorUserOf(requestWithBody({ tmpToken }))).to.equal('10')
    })

    it('ignores tokens that are not signed by the server', () => {
      const [header, , signature] = security.authorize({ userId: 10, type: 'password_valid_needs_second_factor_token' }).split('.')
      const forged = [header, Buffer.from(JSON.stringify({ userId: 1 })).toString('base64url'), signature].join('.')
      expect(rateLimiting.secondFactorUserOf(requestWithBody({ tmpToken: forged }))).to.equal(undefined)
      expect(rateLimiting.secondFactorUserOf(requestWithBody({ tmpToken: 'garbage' }))).to.equal(undefined)
      expect(rateLimiting.secondFactorUserOf(requestWithBody({}))).to.equal(undefined)
    })
  })

  describe('authenticatedUserOf', () => {
    it('returns the id of the user owning the bearer token', () => {
      const token = security.authorize({ data: { id: 42 } })
      security.authenticatedUsers.put(token, { data: { id: 42 } } as any)
      expect(rateLimiting.authenticatedUserOf({ headers: { authorization: 'Bearer ' + token } } as unknown as Request)).to.equal('42')
    })

    it('returns undefined for unknown or missing tokens', () => {
      expect(rateLimiting.authenticatedUserOf({ headers: { authorization: 'Bearer unknown' } } as unknown as Request)).to.equal(undefined)
      expect(rateLimiting.authenticatedUserOf({ headers: {} } as unknown as Request)).to.equal(undefined)
    })
  })
})
