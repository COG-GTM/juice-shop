/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { isSafeProfileImageUrl } from '../../routes/profileImageUrlUpload'
const expect = chai.expect

describe('profileImageUrlUpload', () => {
  describe('isSafeProfileImageUrl', () => {
    it('should accept http and https image URLs', () => {
      expect(isSafeProfileImageUrl('https://www.gravatar.com/avatar/00000000000000000000000000000000')).to.equal(true)
      expect(isSafeProfileImageUrl('http://localhost:3000/assets/public/images/uploads/default.svg')).to.equal(true)
      expect(isSafeProfileImageUrl('https://example.com/image.png?size=100&format=png')).to.equal(true)
    })

    it('should reject URLs that inject additional CSP directives', () => {
      expect(isSafeProfileImageUrl("https://a.png; script-src 'unsafe-inline'")).to.equal(false)
      expect(isSafeProfileImageUrl("https://a.png;script-src%20'unsafe-inline'")).to.equal(false)
      expect(isSafeProfileImageUrl('https://a.png,script-src')).to.equal(false)
      expect(isSafeProfileImageUrl('https://a.png\tscript-src')).to.equal(false)
    })

    it('should reject non-http(s) and relative URLs', () => {
      expect(isSafeProfileImageUrl('javascript:alert(1)')).to.equal(false)
      expect(isSafeProfileImageUrl('data:image/svg+xml,<svg/>')).to.equal(false)
      expect(isSafeProfileImageUrl('cataas.com/cat')).to.equal(false)
      expect(isSafeProfileImageUrl('/assets/public/images/uploads/default.svg')).to.equal(false)
    })

    it('should reject non-string and overly long values', () => {
      expect(isSafeProfileImageUrl(undefined)).to.equal(false)
      expect(isSafeProfileImageUrl(['https://a.png'])).to.equal(false)
      expect(isSafeProfileImageUrl('https://a.png/' + 'a'.repeat(2048))).to.equal(false)
    })
  })
})
