/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// @ts-expect-error FIXME no typescript definitions for z85 :(
import z85 from 'z85'
import chai from 'chai'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import jwt from 'jsonwebtoken'
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

  describe('loadPrivateKey', () => {
    const originalKey = process.env.JWT_PRIVATE_KEY
    const originalKeyFile = process.env.JWT_PRIVATE_KEY_FILE
    const pem = (): string => crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs1', format: 'pem' }).toString()

    afterEach(() => {
      if (originalKey === undefined) delete process.env.JWT_PRIVATE_KEY
      else process.env.JWT_PRIVATE_KEY = originalKey
      if (originalKeyFile === undefined) delete process.env.JWT_PRIVATE_KEY_FILE
      else process.env.JWT_PRIVATE_KEY_FILE = originalKeyFile
    })

    it('reads key from JWT_PRIVATE_KEY with escaped newlines', () => {
      const key = pem()
      process.env.JWT_PRIVATE_KEY = key.replace(/\n/g, '\\n')
      delete process.env.JWT_PRIVATE_KEY_FILE

      expect(security.loadPrivateKey()).to.equal(key)
    })

    it('reads key from file referenced by JWT_PRIVATE_KEY_FILE', () => {
      const key = pem()
      const file = path.join(os.tmpdir(), `jwt-${crypto.randomUUID()}.pem`)
      fs.writeFileSync(file, key)
      delete process.env.JWT_PRIVATE_KEY
      process.env.JWT_PRIVATE_KEY_FILE = file

      try {
        expect(security.loadPrivateKey()).to.equal(key)
      } finally {
        fs.unlinkSync(file)
      }
    })

    it('prefers JWT_PRIVATE_KEY over JWT_PRIVATE_KEY_FILE', () => {
      const key = pem()
      process.env.JWT_PRIVATE_KEY = key
      process.env.JWT_PRIVATE_KEY_FILE = path.join(os.tmpdir(), 'does-not-exist.pem')

      expect(security.loadPrivateKey()).to.equal(key)
    })

    it('generates a fresh RSA key if none is configured', () => {
      delete process.env.JWT_PRIVATE_KEY
      delete process.env.JWT_PRIVATE_KEY_FILE

      const key = security.loadPrivateKey()
      expect(crypto.createPrivateKey(key).asymmetricKeyType).to.equal('rsa')
      expect(security.loadPrivateKey()).to.not.equal(key)
    })
  })

  describe('verify', () => {
    const payload = { data: { email: 'admin@juice-sh.op', role: 'admin' } }

    it('accepts tokens issued by authorize', () => {
      expect(security.verify(security.authorize(payload))).to.equal(true)
    })

    it('rejects RS256 tokens signed with a different private key', () => {
      const foreignKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey
      expect(security.verify(jwt.sign(payload, foreignKey, { algorithm: 'RS256' }))).to.equal(false)
    })

    it('rejects HS256 tokens signed with the public key', () => {
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
      const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
      const signature = crypto.createHmac('sha256', security.publicKey).update(`${header}.${body}`).digest('base64url')
      expect(security.verify(`${header}.${body}.${signature}`)).to.equal(false)
    })

    it('rejects unsigned tokens', () => {
      const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')
      const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
      expect(security.verify(`${header}.${body}.`)).to.equal(false)
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
