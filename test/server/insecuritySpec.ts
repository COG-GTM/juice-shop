/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
// @ts-expect-error FIXME no typescript definitions for z85 :(
import z85 from 'z85'
import chai from 'chai'
import sinon from 'sinon'
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

  describe('JWT signing keys', () => {
    const oldPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8iMz0EaM4BKUqYsIa+ndv3NAn2RxCd5ubVdJJcX43zO6Ko0TFEZx/65gY3BE0O6syCEmUP4qbSd6exou/F+WTISzbQ5FBVPVmhnYhG/kpwt/cIxK5iUn5hm+4tQIDAQABAoGBAI+8xiPoOrA+KMnG/T4jJsG6TsHQcDHvJi7o1IKC/hnIXha0atTX5AUkRRce95qSfvKFweXdJXSQ0JMGJyfuXgU6dI0TcseFRfewXAa/ssxAC+iUVR6KUMh1PE2wXLitfeI6JLvVtrBYswm2I7CtY0q8n5AGimHWVXJPLfGV7m0BAkEA+fqFt2LXbLtyg6wZyxMA/cnmt5Nt3U2dAu77MzFJvibANUNHE4HPLZxjGNXN+a6m0K6TD4kDdh5HfUYLWWRBYQJBANK3carmulBwqzcDBjsJ0YrIONBpCAsXxk8idXb8jL9aNIg15Wumm2enqqObahDHB5jnGOLmbasizvSVqypfM9UCQCQl8xIqy+YgURXzXCN+kwUgHinrutZms87Jyi+D8Br8NY0+Nlf+zHvXAomD2W5CsEK7C+8SLBr3k/TsnRWHJuECQHFE9RA2OP8WoaLPuGCyFXaxzICThSRZYluVnWkZtxsBhW2W8z1b8PvWUE7kMy7TnkzeJS2LSnaNHoyxi7IaPQUCQCwWU4U+v4lD7uYBw00Ga/xt+7+UqFPlPVdz1yyr4q24Zxaw0LgmuEvgU5dycq8N7JxjTubX0MIRR+G9fmDBBl8=
-----END RSA PRIVATE KEY-----`

    it('rejects tokens signed with the old hardcoded private key', () => {
      const token = jwt.sign({ data: { email: 'admin@juice-sh.op' } }, oldPrivateKey, { algorithm: 'RS256' })

      expect(security.verify(token)).to.equal(false)
    })

    it('verifies tokens signed with the active private key', () => {
      expect(security.verify(security.authorize())).to.equal(true)
    })

    it('rejects tokens using the HS256 algorithm', () => {
      const token = jwt.sign({ data: { email: 'admin@juice-sh.op' } }, security.publicKey, { algorithm: 'HS256' })

      expect(security.verify(token)).to.equal(false)
    })
  })

  describe('loadJwtPrivateKey', () => {
    let tempDir: string
    let originalConfiguredKey: string | undefined

    beforeEach(() => {
      tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'jwtkey-'))
      originalConfiguredKey = process.env.JWT_PRIVATE_KEY
      delete process.env.JWT_PRIVATE_KEY
    })

    afterEach(() => {
      sinon.restore()
      if (originalConfiguredKey === undefined) {
        delete process.env.JWT_PRIVATE_KEY
      } else {
        process.env.JWT_PRIVATE_KEY = originalConfiguredKey
      }
      fs.rmSync(tempDir, { recursive: true, force: true })
    })

    it('generates and persists a key when the file is missing', () => {
      const keyFile = path.join(tempDir, 'jwt.key')

      const key = security.loadJwtPrivateKey(keyFile)

      expect(key).to.include('-----END')
      expect(fs.existsSync(keyFile)).to.equal(true)
      expect(fs.readFileSync(keyFile, 'utf8')).to.equal(key)
    })

    it('adopts the winning key when the destination appears after the initial probe', () => {
      const keyFile = path.join(tempDir, 'jwt.key')
      const { privateKey: existingKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
        publicKeyEncoding: { type: 'pkcs1', format: 'pem' }
      })
      fs.writeFileSync(keyFile, existingKey)
      sinon.stub(fs, 'readFileSync').onFirstCall().throws(new Error('ENOENT')).callThrough()

      const key = security.loadJwtPrivateKey(keyFile)

      expect(key).to.equal(existingKey)
    })

    it('fails fast when the existing key file is unusable', () => {
      const keyFile = path.join(tempDir, 'jwt.key')
      const malformedKey = '-----BEGIN RSA PRIVATE KEY-----\nnot-a-complete-key'
      fs.writeFileSync(keyFile, malformedKey)

      expect(() => security.loadJwtPrivateKey(keyFile)).to.throw('JWT_PRIVATE_KEY')
      expect(fs.readFileSync(keyFile, 'utf8')).to.equal(malformedKey)
    })
  })

  describe('JWT middleware', () => {
    it('rejects HS256 tokens in isAuthorized without calling next', () => {
      const token = jwt.sign({ data: { email: 'admin@juice-sh.op' } }, security.publicKey, { algorithm: 'HS256' })
      const req = { headers: { authorization: `Bearer ${token}` } }
      const res = { status: sinon.stub(), json: sinon.spy() }
      const next = sinon.spy()
      res.status.returns(res)

      security.isAuthorized()(req as unknown as Request, res as unknown as any, next)

      expect(res.status.calledWith(401)).to.equal(true)
      expect(res.json.calledOnce).to.equal(true)
      expect(next.called).to.equal(false)
    })

    it('passes RS256 tokens through isAuthorized', () => {
      const token = security.authorize({ data: { email: 'authorized@juice-sh.op' } })
      const req = { headers: { authorization: `Bearer ${token}` } }
      const res = {}
      const next = sinon.spy()

      security.isAuthorized()(req as unknown as Request, res as unknown as any, next)

      expect(next.calledOnce).to.equal(true)
    })

    it('does not register HS256 tokens in updateAuthenticatedUsers', () => {
      const token = jwt.sign({ data: { email: 'admin@juice-sh.op' } }, security.publicKey, { algorithm: 'HS256' })
      const req = { headers: { authorization: `Bearer ${token}` }, cookies: {} }
      const res = { cookie: sinon.spy() }
      const next = sinon.spy()

      security.updateAuthenticatedUsers()(req as unknown as Request, res as unknown as any, next)

      expect(security.authenticatedUsers.get(token)).to.equal(undefined)
      expect(next.calledOnce).to.equal(true)
    })

    it('registers RS256 tokens in updateAuthenticatedUsers', () => {
      const token = security.authorize({ data: { email: 'registered@juice-sh.op' } })
      const req = { headers: {}, cookies: { token } }
      const res = { cookie: sinon.spy() }
      const next = sinon.spy()

      security.updateAuthenticatedUsers()(req as unknown as Request, res as unknown as any, next)

      expect(security.authenticatedUsers.get(token)).to.not.equal(undefined)
      expect(res.cookie.calledWith('token', token)).to.equal(true)
      expect(next.calledOnce).to.equal(true)
    })
  })
})
