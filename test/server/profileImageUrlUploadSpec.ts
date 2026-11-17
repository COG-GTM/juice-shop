/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import http from 'node:http'
import { type AddressInfo } from 'node:net'
import { isBlockedAddress, parseAllowedUrl, fetchExternalImage } from '../../routes/profileImageUrlUpload'
const expect = chai.expect

describe('profileImageUrlUpload', () => {
  describe('isBlockedAddress', () => {
    it('should block loopback, private, link-local and reserved addresses', () => {
      for (const address of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '::1', '::', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1', '::ffff:a9fe:a9fe']) {
        expect(isBlockedAddress(address), address).to.equal(true)
      }
    })

    it('should allow public addresses', () => {
      for (const address of ['1.1.1.1', '8.8.8.8', '2606:4700:4700::1111']) {
        expect(isBlockedAddress(address), address).to.equal(false)
      }
    })
  })

  describe('parseAllowedUrl', () => {
    it('should reject non-http(s) protocols', () => {
      for (const url of ['file:///etc/passwd', 'ftp://example.com/a.png', 'gopher://example.com/', 'data:image/png;base64,AAAA']) {
        expect(() => parseAllowedUrl(url), url).to.throw()
      }
    })

    it('should reject internal IP literals in any notation', () => {
      for (const url of ['http://127.0.0.1:3000/solve/challenges/server-side', 'http://169.254.169.254/latest/meta-data/', 'http://[::1]/', 'http://[::ffff:127.0.0.1]/', 'http://2130706433/', 'http://0x7f.1/', 'http://127.1:3000/']) {
        expect(() => parseAllowedUrl(url), url).to.throw()
      }
    })

    it('should reject embedded credentials and unparsable URLs', () => {
      expect(() => parseAllowedUrl('http://user:pass@example.com/a.png')).to.throw()
      expect(() => parseAllowedUrl('cataas.com/cat')).to.throw()
    })

    it('should accept public http(s) URLs', () => {
      expect(parseAllowedUrl('https://example.com/image.png').hostname).to.equal('example.com')
      expect(parseAllowedUrl('http://1.1.1.1/image.png').hostname).to.equal('1.1.1.1')
    })
  })

  async function expectRejection (promise: Promise<unknown>, pattern: RegExp) {
    try {
      await promise
    } catch (error) {
      expect((error as Error).message).to.match(pattern)
      return
    }
    expect.fail('expected promise to be rejected')
  }

  describe('fetchExternalImage', () => {
    let server: http.Server
    let port: number

    before((done) => {
      server = http.createServer((req, res) => { res.end('internal') })
      server.listen(0, '127.0.0.1', () => {
        port = (server.address() as AddressInfo).port
        done()
      })
    })

    after((done) => { server.close(done) })

    it('should refuse to connect to a hostname resolving to loopback', async () => {
      await expectRejection(fetchExternalImage(`http://localhost:${port}/`), /disallowed host/)
    })

    it('should refuse to connect to a loopback IP literal', async () => {
      await expectRejection(fetchExternalImage(`http://127.0.0.1:${port}/`), /disallowed host/)
    })
  })
})
