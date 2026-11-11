/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { isBlockedAddress, parseImageUrl } from '../../routes/profileImageUrlUpload'
const expect = chai.expect

describe('profileImageUrlUpload', () => {
  describe('isBlockedAddress', () => {
    it('should block loopback, private, link-local and other non-public addresses', () => {
      for (const address of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1',
        '::', '::1', '::ffff:127.0.0.1', '::ffff:a9fe:a9fe', 'fc00::1', 'fd12::1', 'fe80::1', 'ff02::1', '64:ff9b::a00:1', 'not-an-ip']) {
        expect(isBlockedAddress(address), address).to.equal(true)
      }
    })

    it('should allow public addresses', () => {
      for (const address of ['8.8.8.8', '192.0.73.2', '1.1.1.1', '2a04:fa87:fffe::c000:4902', '2606:4700:4700::1111', '::ffff:8.8.8.8']) {
        expect(isBlockedAddress(address), address).to.equal(false)
      }
    })
  })

  describe('parseImageUrl', () => {
    it('should accept public https URLs on the default port', () => {
      expect(parseImageUrl('https://www.gravatar.com/avatar/0.png')?.hostname).to.equal('www.gravatar.com')
    })

    it('should reject non-https, non-default-port, credential-bearing, overlong and internal URLs', () => {
      for (const url of ['http://example.com/a.png', 'data:image/png;base64,AAAA', 'file:///etc/passwd', 'https://example.com:8443/a.png',
        'https://user:pass@example.com/a.png', `https://example.com/${'a'.repeat(2048)}`, 'https://127.0.0.1/a.png', 'https://[::1]/a.png',
        'https://169.254.169.254/latest/meta-data/', 'example.com/a.png', 42, undefined]) {
        expect(parseImageUrl(url), String(url)).to.equal(null)
      }
    })
  })
})
