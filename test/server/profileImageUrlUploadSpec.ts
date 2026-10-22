/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import http from 'node:http'
import { type AddressInfo } from 'node:net'
import { fetchImage, isBlockedAddress } from '../../routes/profileImageUrlUpload'

const expect = chai.expect

async function expectBlocked (url: string) {
  let error: Error | undefined
  try {
    const response = await fetchImage(url)
    response.resume()
  } catch (err) {
    error = err as Error
  }
  expect(error, `expected ${url} to be blocked`).to.be.instanceOf(Error)
}

describe('profileImageUrlUpload', () => {
  describe('isBlockedAddress', () => {
    it('should block loopback, private, link-local and reserved addresses', () => {
      for (const address of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.0.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255', '::', '::1', 'fd00::1', 'fe80::1', '::ffff:127.0.0.1', '::ffff:a9fe:a9fe', '64:ff9b:1::a00:1', '2001:0:4136:e378::1', '2002:7f00:1::1']) {
        expect(isBlockedAddress(address), address).to.equal(true)
      }
    })

    it('should allow public addresses', () => {
      for (const address of ['1.1.1.1', '8.8.8.8', '2606:4700:4700::1111']) {
        expect(isBlockedAddress(address), address).to.equal(false)
      }
    })
  })

  describe('fetchImage', () => {
    let server: http.Server
    let port: number
    let hits: number

    before((done) => {
      hits = 0
      server = http.createServer((req, res) => {
        hits++
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

    it('should reject non-http(s) protocols', async () => {
      await expectBlocked('file:///etc/passwd')
      await expectBlocked('ftp://example.com/image.png')
    })

    it('should reject the cloud metadata endpoint', async () => {
      await expectBlocked('http://169.254.169.254/latest/meta-data/')
    })

    it('should not reach internal services via IP literals or hostnames resolving to them', async () => {
      await expectBlocked(`http://127.0.0.1:${port}/solve/challenges/server-side`)
      await expectBlocked(`http://[::ffff:127.0.0.1]:${port}/`)
      await expectBlocked(`http://localhost:${port}/`)
      expect(hits).to.equal(0)
    })
  })
})
