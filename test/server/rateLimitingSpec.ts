/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { randomUUID } from 'node:crypto'
import express, { type Request, type Response } from 'express'
import request from 'supertest'
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
    it('keys on the exact email the reset route looks up', () => {
      expect(rateLimiting.emailOf(requestWithBody({ email: 'jim@juice-sh.op' }))).to.equal('jim@juice-sh.op')
    })

    it('keeps case variants of an address in separate buckets', () => {
      expect(rateLimiting.emailOf(requestWithBody({ email: 'Alice@example.com' }))).to.not.equal(rateLimiting.emailOf(requestWithBody({ email: 'alice@example.com' })))
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

  describe('secondFactorUserOf', () => {
    it('returns the user id of a validly signed temporary 2FA token', () => {
      const tmpToken = security.authorize({ userId: 10, type: 'password_valid_needs_second_factor_token', expiresAt: security.secondFactorTokenExpiry() })
      expect(rateLimiting.secondFactorUserOf(requestWithBody({ tmpToken }))).to.equal('10')
    })

    it('ignores expired temporary 2FA tokens', () => {
      const tmpToken = security.authorize({ userId: 10, type: 'password_valid_needs_second_factor_token', expiresAt: Date.now() - 1 })
      expect(rateLimiting.secondFactorUserOf(requestWithBody({ tmpToken }))).to.equal(undefined)
    })

    it('ignores tokens of another type', () => {
      const tmpToken = security.authorize({ userId: 10, type: 'totp_setup_secret', expiresAt: security.secondFactorTokenExpiry() })
      expect(rateLimiting.secondFactorUserOf(requestWithBody({ tmpToken }))).to.equal(undefined)
    })

    it('ignores tokens that are not signed by the server', () => {
      const [header, , signature] = security.authorize({ userId: 10, type: 'password_valid_needs_second_factor_token' }).split('.')
      const forged = [header, Buffer.from(JSON.stringify({ userId: 1, type: 'password_valid_needs_second_factor_token', expiresAt: security.secondFactorTokenExpiry() })).toString('base64url'), signature].join('.')
      expect(rateLimiting.secondFactorUserOf(requestWithBody({ tmpToken: forged }))).to.equal(undefined)
      expect(rateLimiting.secondFactorUserOf(requestWithBody({ tmpToken: 'garbage' }))).to.equal(undefined)
      expect(rateLimiting.secondFactorUserOf(requestWithBody({}))).to.equal(undefined)
    })
  })
})

describe('loginRateLimit', () => {
  const validPassword = randomUUID()
  const valid2faPassword = randomUUID()
  const loginApp = (options: { maxPerClient?: number, maxPerAccount?: number }) => {
    const app = express()
    app.use(express.json())
    app.post('/login', ...rateLimiting.loginRateLimit(options), (req: Request, res: Response) => {
      if (req.body.password === validPassword) res.json({ authentication: {} })
      else if (req.body.password === valid2faPassword) res.status(401).json({ status: 'totp_token_required' })
      else res.status(401).send('Invalid email or password.')
    })
    return app
  }

  const attempts = async (app: express.Express, logins: Array<{ email: string, password: string }>) => {
    const statuses: number[] = []
    for (const [i, body] of logins.entries()) {
      statuses.push((await request(app).post('/login').set('X-Forwarded-For', `10.0.0.${i + 1}`).send(body)).status)
    }
    return statuses
  }

  it('locks an account after the allowed number of failed logins, even for the correct password', async () => {
    const app = loginApp({ maxPerAccount: 2 })
    expect(await attempts(app, [
      { email: 'a@b.c', password: 'x' },
      { email: 'a@b.c', password: 'y' },
      { email: 'a@b.c', password: validPassword },
      { email: 'other@b.c', password: validPassword }
    ])).to.deep.equal([401, 401, 429, 200])
  })

  it('caps failed logins per client address regardless of X-Forwarded-For or targeted account', async () => {
    const app = loginApp({ maxPerClient: 3 })
    expect(await attempts(app, [
      { email: '1@b.c', password: 'x' },
      { email: '2@b.c', password: 'x' },
      { email: '3@b.c', password: 'x' },
      { email: '4@b.c', password: validPassword }
    ])).to.deep.equal([401, 401, 401, 429])
  })

  it('does not count successful logins or correct passwords of 2FA accounts', async () => {
    const app = loginApp({ maxPerClient: 2, maxPerAccount: 2 })
    expect(await attempts(app, [
      { email: 'a@b.c', password: validPassword },
      { email: 'a@b.c', password: valid2faPassword },
      { email: 'a@b.c', password: validPassword },
      { email: 'a@b.c', password: valid2faPassword },
      { email: 'a@b.c', password: 'x' },
      { email: 'a@b.c', password: validPassword }
    ])).to.deep.equal([200, 401, 200, 401, 401, 200])
  })
})

describe('isSecondFactorTokenExpired', () => {
  it('accepts a token within its lifetime', () => {
    expect(security.isSecondFactorTokenExpired({ expiresAt: security.secondFactorTokenExpiry() })).to.equal(false)
  })

  it('rejects expired tokens and tokens without expiry', () => {
    expect(security.isSecondFactorTokenExpired({ expiresAt: Date.now() - 1 })).to.equal(true)
    expect(security.isSecondFactorTokenExpired({ expiresAt: String(Date.now() + 60000) })).to.equal(true)
    expect(security.isSecondFactorTokenExpired({})).to.equal(true)
    expect(security.isSecondFactorTokenExpired(undefined)).to.equal(true)
  })
})

describe('verifySecondFactorToken', () => {
  it('returns the payload of a valid, unexpired temporary 2FA token', () => {
    const tmpToken = security.authorize({ userId: 10, type: 'password_valid_needs_second_factor_token', expiresAt: security.secondFactorTokenExpiry() })
    expect(security.verifySecondFactorToken(tmpToken).userId).to.equal(10)
  })

  it('throws for tokens of another type, expired, unsigned or missing tokens', () => {
    const wrongType = security.authorize({ userId: 10, type: 'totp_setup_secret', expiresAt: security.secondFactorTokenExpiry() })
    const expired = security.authorize({ userId: 10, type: 'password_valid_needs_second_factor_token', expiresAt: Date.now() - 1 })
    expect(() => security.verifySecondFactorToken(wrongType)).to.throw('Invalid token type')
    expect(() => security.verifySecondFactorToken(expired)).to.throw('Temporary token expired')
    expect(() => security.verifySecondFactorToken('garbage')).to.throw()
    expect(() => security.verifySecondFactorToken(undefined)).to.throw('Invalid token type')
  })
})
