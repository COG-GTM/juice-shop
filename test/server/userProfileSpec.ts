/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { profileImageCspSource } from '../../routes/userProfile'
const expect = chai.expect

describe('userProfile', () => {
  describe('profileImageCspSource', () => {
    it('should return the origin of an absolute http(s) image URL', () => {
      expect(profileImageCspSource('https://www.gravatar.com/avatar/abc?s=200')).to.equal('https://www.gravatar.com')
      expect(profileImageCspSource('http://localhost:3000/assets/x.png')).to.equal('http://localhost:3000')
      expect(profileImageCspSource('http://[::1]:3000/x.png')).to.equal('http://[::1]:3000')
    })

    it('should ignore relative image paths which are covered by \'self\'', () => {
      expect(profileImageCspSource('/assets/public/images/uploads/default.svg')).to.equal(undefined)
      expect(profileImageCspSource('assets/public/images/uploads/1.png')).to.equal(undefined)
    })

    it('should not allow CSP directives to be injected', () => {
      expect(profileImageCspSource("https://a.png; script-src 'unsafe-inline'")).to.equal(undefined)
      expect(profileImageCspSource("https://a.png;script-src'unsafe-inline'")).to.equal(undefined)
      expect(profileImageCspSource("x; script-src 'unsafe-inline'")).to.equal(undefined)
      expect(profileImageCspSource('https://a.png,script-src')).to.equal(undefined)
      expect(profileImageCspSource("https://a.png'unsafe-inline'")).to.equal(undefined)
    })

    it('should ignore non-http(s) and empty values', () => {
      expect(profileImageCspSource('javascript:alert(1)')).to.equal(undefined)
      expect(profileImageCspSource('data:image/png;base64,AAAA')).to.equal(undefined)
      expect(profileImageCspSource('ftp://example.com/x.png')).to.equal(undefined)
      expect(profileImageCspSource('')).to.equal(undefined)
      expect(profileImageCspSource(undefined)).to.equal(undefined)
    })
  })
})
