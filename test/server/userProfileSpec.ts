/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { profileImageCspSource } from '../../routes/userProfile'

const expect = chai.expect

describe('userProfile', () => {
  describe('profileImageCspSource', () => {
    it('allows only the origin of absolute http(s) image URLs', () => {
      expect(profileImageCspSource('https://images.example.com/cat.png')).to.equal('https://images.example.com')
      expect(profileImageCspSource('http://images.example.com:8080/a/b.jpg?x=1')).to.equal('http://images.example.com:8080')
    })

    it('drops directives smuggled into the profile image', () => {
      expect(profileImageCspSource("https://a.png; script-src 'unsafe-inline' 'self' 'unsafe-eval'")).to.equal('')
      expect(profileImageCspSource("https://a.png/;script-src 'unsafe-inline'")).to.equal('https://a.png')
    })

    it('ignores relative, non-http and missing profile images', () => {
      expect(profileImageCspSource('/assets/public/images/uploads/default.svg')).to.equal('')
      expect(profileImageCspSource("javascript:alert('xss')")).to.equal('')
      expect(profileImageCspSource('data:image/png;base64,AAAA')).to.equal('')
      expect(profileImageCspSource(undefined)).to.equal('')
      expect(profileImageCspSource('')).to.equal('')
    })
  })
})
