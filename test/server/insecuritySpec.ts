/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// @ts-expect-error FIXME no typescript definitions for z85 :(
import z85 from 'z85'
import chai from 'chai'
import sinon from 'sinon'
import * as security from '../../lib/insecurity'
import type { UserModel } from 'models/user'
import type { Request, Response } from 'express'
const expect = chai.expect

describe('insecurity', () => {
  describe('cutOffPoisonNullByte', () => {
    it('returns string unchanged if it contains no null byte', () => {
      expect(security.cutOffPoisonNullByte('file.exe.pdf')).to.equal('file.exe.pdf')
    })

    it('returns string up to null byte', () => {
      expect(security.cutOffPoisonNullByte('file.exe%00.pdf')).to.equal('file.exe')
    })
  })

  describe('userEmailFrom', () => {
    it('returns content of "x-user-email" header if present', () => {
      expect(security.userEmailFrom({ headers: { 'x-user-email': 'test@bla.blubb' } })).to.equal('test@bla.blubb')
    })

    it('returns undefined if header "x-user-email" is not present', () => {
      expect(security.userEmailFrom({ headers: {} })).to.equal(undefined)
      expect(security.userEmailFrom({})).to.equal(undefined)
    })
  })

  describe('generateCoupon', () => {
    it('returns base85-encoded month, year and discount as coupon code', () => {
      const coupon = security.generateCoupon(20, new Date('1980-01-02'))
      expect(coupon).to.equal('n<MiifFb4l')
      expect(z85.decode(coupon).toString()).to.equal('JAN80-20')
    })

    it('uses current month and year if not specified', () => {
      const coupon = security.generateCoupon(20)
      expect(coupon).to.equal(security.generateCoupon(20, new Date()))
    })

    it('does not encode day of month or time into coupon code', () => {
      const coupon = security.generateCoupon(10, new Date('December 01, 1999'))
      expect(coupon).to.equal(security.generateCoupon(10, new Date('December 01, 1999 01:00:00')))
      expect(coupon).to.equal(security.generateCoupon(10, new Date('December 02, 1999')))
      expect(coupon).to.equal(security.generateCoupon(10, new Date('December 31, 1999 23:59:59')))
    })
  })

  describe('discountFromCoupon', () => {
    it('returns undefined when not passing in a coupon code', () => {
      expect(security.discountFromCoupon(undefined)).to.equal(undefined)
    })

    it('returns undefined for malformed coupon code', () => {
      expect(security.discountFromCoupon('')).to.equal(undefined)
      expect(security.discountFromCoupon('x')).to.equal(undefined)
      expect(security.discountFromCoupon('___')).to.equal(undefined)
    })

    it('returns undefined for coupon code not according to expected pattern', () => {
      expect(security.discountFromCoupon(z85.encode('Test'))).to.equal(undefined)
      expect(security.discountFromCoupon(z85.encode('XXX00-10'))).to.equal(undefined)
      expect(security.discountFromCoupon(z85.encode('DEC18-999'))).to.equal(undefined)
      expect(security.discountFromCoupon(z85.encode('DEC18-1'))).to.equal(undefined)
      expect(security.discountFromCoupon(z85.encode('DEC2018-10'))).to.equal(undefined)
    })

    it('returns undefined for expired coupon code', () => {
      expect(security.discountFromCoupon(z85.encode('SEP14-50'))).to.equal(undefined)
    })

    it('returns discount from valid coupon code', () => {
      expect(security.discountFromCoupon(security.generateCoupon(10))).to.equal(10)
      expect(security.discountFromCoupon(security.generateCoupon(99))).to.equal(99)
    })
  })

  describe('authenticatedUsers', () => {
    const sixHoursAndOneMinute = (6 * 60 + 1) * 60 * 1000
    const sessionFor = (id: number) => security.authorize({ data: { id } })
    const payloadOf = (token: string) => JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'))
    let clock: sinon.SinonFakeTimers | undefined

    beforeEach(() => {
      security.authenticatedUsers.tokenMap = {}
      security.authenticatedUsers.idMap = {}
      security.authenticatedUsers.revokedTokens = {}
      security.authenticatedUsers.lastSweep = 0
    })

    afterEach(() => {
      clock?.restore()
      clock = undefined
    })

    it('returns user by associated token', () => {
      const token = sessionFor(1)
      security.authenticatedUsers.put(token, { data: { id: 1 } as unknown as UserModel })

      expect(security.authenticatedUsers.get(token)).to.deep.equal({ data: { id: 1 } })
    })

    it('returns undefined if no token is passed in', () => {
      expect(security.authenticatedUsers.get(undefined)).to.equal(undefined)
    })

    it('returns token by associated user', () => {
      const token = sessionFor(1)
      security.authenticatedUsers.put(token, { data: { id: 1 } as unknown as UserModel })

      expect(security.authenticatedUsers.tokenOf({ id: 1 } as unknown as UserModel)).to.equal(token)
    })

    it('returns user by associated token from request', () => {
      const token = sessionFor(1)
      security.authenticatedUsers.put(token, { data: { id: 1 } as unknown as UserModel })

      expect(security.authenticatedUsers.from({ headers: { authorization: `Bearer ${token}` } } as unknown as Request)).to.deep.equal({ data: { id: 1 } })
    })

    it('returns undefined if no token is present in request', () => {
      expect(security.authenticatedUsers.from({ headers: {} } as unknown as Request)).to.equal(undefined)
      expect(security.authenticatedUsers.from({} as unknown as Request)).to.equal(undefined)
    })

    it('issues tokens that expire after six hours', () => {
      const { exp } = payloadOf(sessionFor(1))

      expect(exp - Math.floor(Date.now() / 1000)).to.be.within(6 * 60 * 60 - 5, 6 * 60 * 60)
    })

    it('does not cache tokens with a tampered payload', () => {
      const [header, , signature] = sessionFor(1).split('.')
      const tampered = `${header}.${Buffer.from(JSON.stringify({ data: { id: 2 }, exp: Math.floor(Date.now() / 1000) + 60 })).toString('base64url')}.${signature}`
      security.authenticatedUsers.put(tampered, { data: { id: 2 } as unknown as UserModel })

      expect(security.authenticatedUsers.get(tampered)).to.equal(undefined)
      expect(security.authenticatedUsers.tokenMap).to.not.have.property(tampered)
    })

    it('evicts cached users once their token has expired', () => {
      clock = sinon.useFakeTimers({ now: Date.now(), toFake: ['Date'] })
      const token = sessionFor(1)
      security.authenticatedUsers.put(token, { data: { id: 1 } as unknown as UserModel })

      clock.tick(sixHoursAndOneMinute)

      expect(security.authenticatedUsers.get(token)).to.equal(undefined)
      expect(security.authenticatedUsers.from({ headers: { authorization: `Bearer ${token}` } } as unknown as Request)).to.equal(undefined)
      expect(security.authenticatedUsers.tokenMap).to.not.have.property(token)
      expect(security.authenticatedUsers.tokenOf({ id: 1 } as unknown as UserModel)).to.equal(undefined)
    })

    it('sweeps expired tokens of other users when a new session is stored', () => {
      clock = sinon.useFakeTimers({ now: Date.now(), toFake: ['Date'] })
      const staleToken = sessionFor(1)
      security.authenticatedUsers.put(staleToken, { data: { id: 1 } as unknown as UserModel })

      clock.tick(sixHoursAndOneMinute)
      security.authenticatedUsers.put(sessionFor(2), { data: { id: 2 } as unknown as UserModel })

      expect(security.authenticatedUsers.tokenMap).to.not.have.property(staleToken)
      expect(Object.keys(security.authenticatedUsers.tokenMap)).to.have.length(1)
    })

    it('revokes a token so that it can no longer be cached', () => {
      const token = sessionFor(1)
      security.authenticatedUsers.put(token, { data: { id: 1 } as unknown as UserModel })

      security.authenticatedUsers.revoke(token)
      security.authenticatedUsers.put(token, { data: { id: 1 } as unknown as UserModel })

      expect(security.authenticatedUsers.isRevoked(token)).to.equal(true)
      expect(security.authenticatedUsers.get(token)).to.equal(undefined)
      expect(security.authenticatedUsers.tokenOf({ id: 1 } as unknown as UserModel)).to.equal(undefined)
    })

    it('forgets revocations once the revoked token has expired', () => {
      clock = sinon.useFakeTimers({ now: Date.now(), toFake: ['Date'] })
      const token = sessionFor(1)
      security.authenticatedUsers.revoke(token)

      clock.tick(sixHoursAndOneMinute)
      security.authenticatedUsers.sweep()

      expect(security.authenticatedUsers.revokedTokens).to.deep.equal({})
    })

    it('revokes all other sessions of a user but keeps the current one', async () => {
      const first = sessionFor(1)
      security.authenticatedUsers.put(first, { data: { id: 1 } as unknown as UserModel })
      await new Promise((resolve) => setTimeout(resolve, 1100))
      const current = sessionFor(1)
      const otherUser = sessionFor(2)
      security.authenticatedUsers.put(current, { data: { id: 1 } as unknown as UserModel })
      security.authenticatedUsers.put(otherUser, { data: { id: 2 } as unknown as UserModel })

      security.authenticatedUsers.revokeAllFor(1, current)

      expect(security.authenticatedUsers.get(first)).to.equal(undefined)
      expect(security.authenticatedUsers.get(current)).to.deep.equal({ data: { id: 1 } })
      expect(security.authenticatedUsers.get(otherUser)).to.deep.equal({ data: { id: 2 } })
    })

    it('does not re-cache a revoked token via updateAuthenticatedUsers', () => {
      const token = sessionFor(1)
      const res = { cookie: sinon.spy() }
      const next = sinon.spy()
      security.authenticatedUsers.revoke(token)

      security.updateAuthenticatedUsers()({ cookies: { token }, headers: {} } as unknown as Request, res as unknown as Response, next)

      expect(security.authenticatedUsers.get(token)).to.equal(undefined)
      expect(res.cookie.called).to.equal(false)
      expect(next.calledOnce).to.equal(true)
    })

    it('rejects a revoked token in isAuthorized', async () => {
      const token = sessionFor(1)
      security.authenticatedUsers.revoke(token)

      const err = await new Promise<any>((resolve) => {
        security.isAuthorized()({ headers: { authorization: `Bearer ${token}` } } as unknown as Request, {} as unknown as Response, resolve)
      })

      expect(err?.status).to.equal(401)
    })

    it('accepts a live token in isAuthorized', async () => {
      const token = sessionFor(1)

      const err = await new Promise<any>((resolve) => {
        security.isAuthorized()({ headers: { authorization: `Bearer ${token}` } } as unknown as Request, {} as unknown as Response, resolve)
      })

      expect(err).to.equal(undefined)
    })

    it('answers 401 in appendUserId for an expired token', () => {
      clock = sinon.useFakeTimers({ now: Date.now(), toFake: ['Date'] })
      const token = sessionFor(1)
      security.authenticatedUsers.put(token, { data: { id: 1 } as unknown as UserModel })
      clock.tick(sixHoursAndOneMinute)
      const json = sinon.spy()
      const res = { status: sinon.stub().returns({ json }) }
      const next = sinon.spy()

      security.appendUserId()({ headers: { authorization: `Bearer ${token}` }, body: {} } as unknown as Request, res as unknown as Response, next)

      expect(res.status.calledWith(401)).to.equal(true)
      expect(next.called).to.equal(false)
    })
  })

  describe('sanitizeLegacy', () => {
    it('returns empty string for undefined input', () => {
      expect(security.sanitizeLegacy()).to.equal('')
      expect(security.sanitizeLegacy(undefined)).to.equal('')
    })

    it('returns input unchanged for plain text input', () => {
      expect(security.sanitizeLegacy('bkimminich')).to.equal('bkimminich')
      expect(security.sanitizeLegacy('Kosh III.')).to.equal('Kosh III.')
    })

    it('removes all opening tags and subsequent character from HTML input', () => {
      expect(security.sanitizeLegacy('<h1>Hello</h1>')).to.equal('ello</h1>')
      expect(security.sanitizeLegacy('<img src="test">')).to.equal('rc="test">')
    })

    it('can be bypassed to allow working HTML payload to be returned', () => {
      expect(security.sanitizeLegacy('<<a|ascript>alert(`xss`)</script>')).to.equal('<script>alert(`xss`)</script>')
    })
  })

  describe('sanitizeSecure', () => {
    it('handles empty inputs by returning their string representation', () => {
      expect(security.sanitizeSecure('')).to.equal('')
    })

    it('returns input unchanged for plain text input', () => {
      expect(security.sanitizeSecure('This application is horrible!')).to.equal('This application is horrible!')
    })

    it('returns input unchanged for HTML input with only harmless text formatting', () => {
      expect(security.sanitizeSecure('<strong>This</strong> application <em>is horrible</em>!')).to.equal('<strong>This</strong> application <em>is horrible</em>!')
    })

    it('returns input unchanged for HTML input with only harmless links', () => {
      expect(security.sanitizeSecure('<a href="bla.blubb">Please see here for details!</a>')).to.equal('<a href="bla.blubb">Please see here for details!</a>')
    })

    it('removes all Javascript from HTML input', () => {
      expect(security.sanitizeSecure('Sani<script>alert("ScriptXSS")</script>tizedScript')).to.equal('SanitizedScript')
      expect(security.sanitizeSecure('Sani<img src="alert("ImageXSS")"/>tizedImage')).to.equal('SanitizedImage')
      expect(security.sanitizeSecure('Sani<iframe src="alert("IFrameXSS")"></iframe>tizedIFrame')).to.equal('SanitizedIFrame')
    })

    it('cannot be bypassed by exploiting lack of recursive sanitization', () => {
      expect(security.sanitizeSecure('Bla<<script>Foo</script>iframe src="javascript:alert(`xss`)">Blubb')).to.equal('BlaBlubb')
    })
  })

  describe('hash', () => {
    it('returns MD5 hash for any input string', () => {
      expect(security.hash('admin123')).to.equal('0192023a7bbd73250516f069df18b500')
      expect(security.hash('password')).to.equal('5f4dcc3b5aa765d61d8327deb882cf99')
      expect(security.hash('')).to.equal('d41d8cd98f00b204e9800998ecf8427e')
    })
  })

  describe('hmac', () => {
    it('returns SHA-256 HMAC with "pa4qacea4VK9t9nGv7yZtwmj" as salt any input string', () => {
      expect(security.hmac('admin123')).to.equal('6be13e2feeada221f29134db71c0ab0be0e27eccfc0fb436ba4096ba73aafb20')
      expect(security.hmac('password')).to.equal('da28fc4354f4a458508a461fbae364720c4249c27f10fccf68317fc4bf6531ed')
      expect(security.hmac('')).to.equal('f052179ec5894a2e79befa8060cfcb517f1e14f7f6222af854377b6481ae953e')
    })
  })
})
