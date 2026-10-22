/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { profileImageCspSource } from '../../routes/userProfile'

const expect = chai.expect

describe('userProfile', () => {
  describe('profileImageCspSource', () => {
    it('returns only the origin of an absolute http(s) image URL', () => {
      expect(profileImageCspSource('https://www.gravatar.com/avatar/abc?s=200')).to.equal('https://www.gravatar.com')
      expect(profileImageCspSource('http://localhost:3000/assets/public/images/uploads/1.jpg')).to.equal('http://localhost:3000')
      expect(profileImageCspSource('http://[2001:db8::1]:8080/photo.jpg')).to.equal('http://[2001:db8::1]:8080')
    })

    it('adds no source for same-origin paths', () => {
      expect(profileImageCspSource('/assets/public/images/uploads/default.svg')).to.equal('')
      expect(profileImageCspSource('assets/public/images/uploads/1.png')).to.equal('')
    })

    it('rejects values that would inject CSP directives', () => {
      expect(profileImageCspSource("https://a.png; script-src 'unsafe-inline'")).to.equal('')
      expect(profileImageCspSource("https://a;script-src/'unsafe-inline'")).to.equal('')
      expect(profileImageCspSource("https://a'b/x")).to.equal('')
      expect(profileImageCspSource("x; script-src 'unsafe-inline'")).to.equal('')
      expect(profileImageCspSource('javascript:alert(1)')).to.equal('')
      expect(profileImageCspSource(undefined)).to.equal('')
    })
  })
})
