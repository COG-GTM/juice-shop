/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import http from 'node:http'
import { type AddressInfo } from 'node:net'
import chai from 'chai'
import { fetchImage, isBlockedAddress, parseImageUrl } from '../../routes/profileImageUrlUpload'
const expect = chai.expect

describe('profileImageUrlUpload', () => {
  describe('isBlockedAddress', () => {
    for (const address of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '::1', '::', '::ffff:127.0.0.1', '::ffff:a9fe:a9fe', 'fe80::1', 'fd00::1', '64:ff9b::7f00:1', '2002:7f00:1::', 'not-an-ip']) {
      it(`should block ${address}`, () => {
        expect(isBlockedAddress(address)).to.equal(true)
      })
    }

    for (const address of ['1.1.1.1', '93.184.216.34', '2606:4700:4700::1111']) {
      it(`should allow ${address}`, () => {
        expect(isBlockedAddress(address)).to.equal(false)
      })
    }
  })

  describe('parseImageUrl', () => {
    for (const url of ['file:///etc/passwd', 'gopher://example.com/', 'ftp://example.com/a.png', 'cataas.com/cat', 'http://127.0.0.1:3000/solve/challenges/server-side', 'http://2130706433/', 'http://0x7f.1/', 'http://[::1]/', 'http://[::ffff:127.0.0.1]/', 'http://169.254.169.254/latest/meta-data/', 'https://user:pass@example.com/a.png']) {
      it(`should reject ${url}`, () => {
        expect(() => parseImageUrl(url)).to.throw()
      })
    }

    it('should reject non-string input', () => {
      expect(() => parseImageUrl(['http://example.com/a.png'])).to.throw()
    })

    it('should accept public http(s) URLs', () => {
      expect(parseImageUrl('https://example.com/a.png').hostname).to.equal('example.com')
      expect(parseImageUrl('http://1.1.1.1/a.png').hostname).to.equal('1.1.1.1')
    })
  })

  describe('fetchImage', () => {
    let server: http.Server
    let port: number
    let requests: number

    before((done) => {
      requests = 0
      server = http.createServer((req, res) => {
        requests++
        res.end('internal')
      })
      server.listen(0, '127.0.0.1', () => {
        port = (server.address() as AddressInfo).port
        done()
      })
    })

    after((done) => {
      server.close(done)
    })

    it('should not connect to hostnames resolving to loopback', async () => {
      let error: Error | undefined
      try {
        await fetchImage(new URL(`http://localhost:${port}/solve/challenges/server-side`))
      } catch (err) {
        error = err as Error
      }
      expect(error?.message).to.match(/disallowed address/)
      expect(requests).to.equal(0)
    })
  })
})
