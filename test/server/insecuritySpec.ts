/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// @ts-expect-error FIXME no typescript definitions for z85 :(
import z85 from 'z85'
import chai from 'chai'
import * as security from '../../lib/insecurity'
import type { UserModel } from 'models/user'
import type { Request } from 'express'
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
    it('returns user by associated token', () => {
      security.authenticatedUsers.put('11111', { data: { id: 1 } as unknown as UserModel })

      expect(security.authenticatedUsers.get('11111')).to.deep.equal({ data: { id: 1 } })
    })

    it('returns undefined if no token is passed in', () => {
      expect(security.authenticatedUsers.get(undefined)).to.equal(undefined)
    })

    it('returns token by associated user', () => {
      security.authenticatedUsers.put('11111', { data: { id: 1 } as unknown as UserModel })

      expect(security.authenticatedUsers.tokenOf({ id: 1 } as unknown as UserModel)).to.equal('11111')
    })

    it('returns user by associated token from request', () => {
      security.authenticatedUsers.put('11111', { data: { id: 1 } as unknown as UserModel })

      expect(security.authenticatedUsers.from({ headers: { authorization: 'Bearer 11111' } } as unknown as Request)).to.deep.equal({ data: { id: 1 } })
    })

    it('returns undefined if no token is present in request', () => {
      expect(security.authenticatedUsers.from({ headers: {} } as unknown as Request)).to.equal(undefined)
      expect(security.authenticatedUsers.from({} as unknown as Request)).to.equal(undefined)
    })

    describe('session store bounds', () => {
      const originalLimits = { ...security.sessionLimits }

      afterEach(() => {
        Object.assign(security.sessionLimits, originalLimits)
        for (const token of [...security.authenticatedUsers.expiries.keys()]) {
          security.authenticatedUsers.remove(token)
        }
      })

      it('forgets a session once its JWT has expired', () => {
        const nowInSeconds = Math.floor(Date.now() / 1000)
        security.authenticatedUsers.put('expired', { data: { id: 42 } as unknown as UserModel, exp: nowInSeconds - 1 })
        security.authenticatedUsers.put('valid', { data: { id: 43 } as unknown as UserModel, exp: nowInSeconds + 60 })

        expect(security.authenticatedUsers.get('expired')).to.equal(undefined)
        expect(security.authenticatedUsers.get('valid')).to.deep.equal({ data: { id: 43 }, exp: nowInSeconds + 60 })
        expect(security.authenticatedUsers.tokenMap).to.not.have.property('expired')
      })

      it('uses the exp claim of the token when the user object has none', () => {
        const exp = Math.floor(Date.now() / 1000) + 120
        const token = ['{"alg":"none"}', JSON.stringify({ data: { id: 44 }, exp })].map(part => Buffer.from(part).toString('base64url')).join('.') + '.'
        security.authenticatedUsers.put(token, { data: { id: 44 } as unknown as UserModel })

        expect(security.authenticatedUsers.expiries.get(token)).to.equal(exp * 1000)
      })

      it('expires an issued token no later than six hours after login', () => {
        const before = Date.now()
        const token = security.authorize({ data: { id: 53 } })
        security.authenticatedUsers.put(token, { data: { id: 53 } as unknown as UserModel })

        const expiry = security.authenticatedUsers.expiries.get(token) as number
        expect(expiry).to.be.above(before)
        expect(expiry).to.be.at.most(Date.now() + security.sessionLimits.defaultTtlMs)
      })

      it('removes expired sessions when a new session is stored', () => {
        security.authenticatedUsers.put('stale', { data: { id: 45 } as unknown as UserModel, exp: Math.floor(Date.now() / 1000) - 1 })
        security.authenticatedUsers.put('fresh', { data: { id: 46 } as unknown as UserModel })

        expect(security.authenticatedUsers.tokenMap).to.not.have.property('stale')
        expect(security.authenticatedUsers.idMap).to.not.have.property('45')
      })

      it('keeps only the newest sessions of a user who logs in repeatedly', () => {
        security.sessionLimits.maxSessionsPerUser = 3
        for (let i = 1; i <= 5; i++) {
          security.authenticatedUsers.put(`login${i}`, { data: { id: 47 } as unknown as UserModel })
        }
        security.authenticatedUsers.put('otherUser', { data: { id: 48 } as unknown as UserModel })

        expect(Object.keys(security.authenticatedUsers.tokenMap)).to.have.members(['login3', 'login4', 'login5', 'otherUser'])
        expect(security.authenticatedUsers.tokenOf({ id: 47 } as unknown as UserModel)).to.equal('login5')
      })

      it('never stores more than the maximum number of sessions', () => {
        security.sessionLimits.maxSessions = 100
        for (let i = 0; i < 1000; i++) {
          security.authenticatedUsers.put(`token${i}`, { data: { id: i } as unknown as UserModel })
        }

        expect(Object.keys(security.authenticatedUsers.tokenMap)).to.have.length(100)
        expect(security.authenticatedUsers.expiries.size).to.equal(100)
        expect(Object.keys(security.authenticatedUsers.idMap)).to.have.length(100)
        expect(security.authenticatedUsers.get('token999')).to.deep.equal({ data: { id: 999 } })
        expect(security.authenticatedUsers.get('token0')).to.equal(undefined)
      })

      it('removes a session and its user mapping', () => {
        security.authenticatedUsers.put('toRemove', { data: { id: 49 } as unknown as UserModel })
        security.authenticatedUsers.remove('toRemove')

        expect(security.authenticatedUsers.get('toRemove')).to.equal(undefined)
        expect(security.authenticatedUsers.tokenOf({ id: 49 } as unknown as UserModel)).to.equal(undefined)
      })

      it('maps the user to a remaining session when the newest one is removed', () => {
        security.authenticatedUsers.put('olderToken', { data: { id: 50 } as unknown as UserModel })
        security.authenticatedUsers.put('newerToken', { data: { id: 50 } as unknown as UserModel })
        security.authenticatedUsers.remove('newerToken')

        expect(security.authenticatedUsers.tokenOf({ id: 50 } as unknown as UserModel)).to.equal('olderToken')
      })

      it('does not report an expired session from tokenOf', () => {
        const expiredUser = { data: { id: 51 } as unknown as UserModel, exp: Math.floor(Date.now() / 1000) - 1 }
        security.authenticatedUsers.put('expiredOnlyToken', expiredUser)

        expect(security.authenticatedUsers.tokenOf({ id: 51 } as unknown as UserModel)).to.equal(undefined)
        expect(security.authenticatedUsers.tokenMap.expiredOnlyToken).to.equal(undefined)
      })

      it('drops the per-user token index once a user has no sessions left', () => {
        security.authenticatedUsers.put('indexedToken', { data: { id: 52 } as unknown as UserModel })
        expect(security.authenticatedUsers.userTokens.get(52)?.has('indexedToken')).to.equal(true)

        security.authenticatedUsers.remove('indexedToken')

        expect(security.authenticatedUsers.userTokens.has(52)).to.equal(false)
      })
    })
  })

  describe('sanitizeHtml', () => {
    it('handles empty inputs by returning their string representation', () => {
      expect(security.sanitizeHtml('')).to.equal('')
    })

    it('returns input unchanged for plain text input', () => {
      expect(security.sanitizeHtml('This application is horrible!')).to.equal('This application is horrible!')
    })

    it('returns input unchanged for HTML input with only harmless text formatting', () => {
      expect(security.sanitizeHtml('<strong>This</strong> application <em>is horrible</em>!')).to.equal('<strong>This</strong> application <em>is horrible</em>!')
    })

    it('returns input unchanged for HTML input with only harmless links', () => {
      expect(security.sanitizeHtml('<a href="bla.blubb">Please see here for details!</a>')).to.equal('<a href="bla.blubb">Please see here for details!</a>')
    })

    it('removes all Javascript from HTML input', () => {
      expect(security.sanitizeHtml('Sani<script>alert("ScriptXSS")</script>tizedScript')).to.equal('SanitizedScript')
      expect(security.sanitizeHtml('Sani<img src="alert("ImageXSS")"/>tizedImage')).to.equal('SanitizedImage')
      expect(security.sanitizeHtml('Sani<iframe src="alert("IFrameXSS")"></iframe>tizedIFrame')).to.equal('SanitizedIFrame')
    })

    it('can be bypassed by exploiting lack of recursive sanitization', () => {
      expect(security.sanitizeHtml('<<script>Foo</script>iframe src="javascript:alert(`xss`)">')).to.equal('<iframe src="javascript:alert(`xss`)">')
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
