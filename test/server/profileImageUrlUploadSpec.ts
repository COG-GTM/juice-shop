/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { isUrlAllowed } from '../../routes/profileImageUrlUpload'
const expect = chai.expect

describe('profileImageUrlUpload', () => {
  describe('isUrlAllowed', () => {
    it('should reject URLs without an http(s) scheme', async () => {
      expect(await isUrlAllowed('ftp://example.com/image.png')).to.equal(false)
      expect(await isUrlAllowed('file:///etc/passwd')).to.equal(false)
      expect(await isUrlAllowed('not a url')).to.equal(false)
      expect(await isUrlAllowed('cataas.com/cat')).to.equal(false)
    })

    it('should reject the cloud metadata endpoint', async () => {
      expect(await isUrlAllowed('http://169.254.169.254/latest/meta-data/')).to.equal(false)
    })

    it('should reject loopback addresses', async () => {
      expect(await isUrlAllowed('http://127.0.0.1:3000/solve/challenges/server-side')).to.equal(false)
      expect(await isUrlAllowed('http://[::1]/')).to.equal(false)
    })

    it('should reject private and reserved IP ranges', async () => {
      expect(await isUrlAllowed('http://10.0.0.1/')).to.equal(false)
      expect(await isUrlAllowed('http://172.16.0.1/')).to.equal(false)
      expect(await isUrlAllowed('http://192.168.1.1/')).to.equal(false)
      expect(await isUrlAllowed('http://0.0.0.0/')).to.equal(false)
      expect(await isUrlAllowed('http://100.64.0.1/')).to.equal(false)
    })

    it('should reject IPv4-mapped IPv6 loopback', async () => {
      expect(await isUrlAllowed('http://[::ffff:127.0.0.1]/')).to.equal(false)
    })

    it('should allow a public IP literal', async () => {
      expect(await isUrlAllowed('https://1.1.1.1/image.png')).to.equal(true)
    })
  })
})
