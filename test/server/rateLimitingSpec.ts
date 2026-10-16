/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import * as security from '../../lib/insecurity'
import { trustedProxies, emailOf, secondFactorUserOf, loginWasSuccessful } from '../../lib/rateLimiting'

const expect = chai.expect

describe('rateLimiting', () => {
  describe('trustedProxies', () => {
    it('does not trust X-Forwarded-For unless configured', () => {
      expect(trustedProxies(undefined)).to.equal(false)
      expect(trustedProxies('')).to.equal(false)
      expect(trustedProxies('0')).to.equal(false)
      expect(trustedProxies('false')).to.equal(false)
    })

    it('accepts a number of trusted proxy hops', () => {
      expect(trustedProxies('2')).to.equal(2)
    })

    it('accepts a list of trusted proxy addresses', () => {
      expect(trustedProxies('loopback, 10.0.0.0/8')).to.deep.equal(['loopback', '10.0.0.0/8'])
    })
  })

  describe('emailOf', () => {
    it('normalizes the email so case variants share one budget', () => {
      expect(emailOf({ body: { email: ' Morty@Juice-sh.op ' } } as any)).to.equal('morty@juice-sh.op')
    })

    it('ignores missing or non-string emails', () => {
      expect(emailOf({ body: {} } as any)).to.equal(undefined)
      expect(emailOf({ body: { email: ['a@b.c'] } } as any)).to.equal(undefined)
    })
  })

  describe('secondFactorUserOf', () => {
    it('returns the user id of a valid 2FA tmpToken', () => {
      const tmpToken = security.authorize({ userId: 10, type: 'password_valid_needs_second_factor_token' })
      expect(secondFactorUserOf({ body: { tmpToken } } as any)).to.equal('10')
    })

    it('ignores invalid tmpTokens', () => {
      expect(secondFactorUserOf({ body: { tmpToken: 'invalid' } } as any)).to.equal(undefined)
      expect(secondFactorUserOf({ body: {} } as any)).to.equal(undefined)
    })
  })

  describe('loginWasSuccessful', () => {
    it('treats a 2FA challenge after a correct password as successful', () => {
      expect(loginWasSuccessful({} as any, { statusCode: 401, locals: { secondFactorRequired: true } } as any)).to.equal(true)
    })

    it('treats other 401 responses as failed logins', () => {
      expect(loginWasSuccessful({} as any, { statusCode: 401, locals: {} } as any)).to.equal(false)
      expect(loginWasSuccessful({} as any, { statusCode: 200, locals: {} } as any)).to.equal(true)
    })
  })
})
