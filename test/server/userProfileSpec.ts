/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { profileImageCspSource } from '../../routes/userProfile'
import { isLinkableImageUrl } from '../../routes/profileImageUrlUpload'
const expect = chai.expect

describe('userProfile', () => {
  describe('profileImageCspSource', () => {
    it('returns only the origin of an http(s) image URL', () => {
      expect(profileImageCspSource('https://www.gravatar.com/avatar/abc?s=200')).to.equal('https://www.gravatar.com')
      expect(profileImageCspSource('http://localhost:3000/assets/public/images/uploads/1.png')).to.equal('http://localhost:3000')
    })

    it('returns nothing for local upload paths and empty values', () => {
      expect(profileImageCspSource('/assets/public/images/uploads/default.svg')).to.equal('')
      expect(profileImageCspSource('')).to.equal('')
      expect(profileImageCspSource(undefined)).to.equal('')
      expect(profileImageCspSource(null)).to.equal('')
    })

    it('cannot be used to add CSP directives', () => {
      expect(profileImageCspSource("; script-src 'unsafe-inline'")).to.equal('')
      expect(profileImageCspSource("https://a.png; script-src 'unsafe-inline' 'self' 'unsafe-eval'")).to.not.contain(';')
      expect(profileImageCspSource("https://a.png; script-src 'unsafe-inline' 'self' 'unsafe-eval'")).to.not.contain('script-src')
      expect(profileImageCspSource("javascript:alert('xss')")).to.equal('')
    })
  })

  describe('isLinkableImageUrl', () => {
    it('accepts absolute http(s) URLs', () => {
      expect(isLinkableImageUrl('https://www.gravatar.com/avatar/abc')).to.equal(true)
      expect(isLinkableImageUrl('http://example.com/a.png')).to.equal(true)
    })

    it('rejects CSP fragments, other schemes and non-strings', () => {
      expect(isLinkableImageUrl("; script-src 'unsafe-inline'")).to.equal(false)
      expect(isLinkableImageUrl("https://a.png; script-src 'unsafe-inline'")).to.equal(false)
      expect(isLinkableImageUrl('https://a.png,https://b.png')).to.equal(false)
      expect(isLinkableImageUrl('javascript:alert(1)')).to.equal(false)
      expect(isLinkableImageUrl('/assets/public/images/uploads/1.png')).to.equal(false)
      expect(isLinkableImageUrl(['https://a.png'])).to.equal(false)
      expect(isLinkableImageUrl(undefined)).to.equal(false)
    })
  })
})
