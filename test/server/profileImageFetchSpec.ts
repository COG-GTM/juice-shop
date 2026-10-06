/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import http from 'node:http'
import { type AddressInfo } from 'node:net'
import { fetchProfileImage, isPublicAddress, MAX_PROFILE_IMAGE_BYTES } from '../../lib/profileImageFetch'

const expect = chai.expect

async function expectRejection (promise: Promise<unknown>, message: RegExp) {
  try {
    await promise
  } catch (error) {
    expect((error as Error).message).to.match(message)
    return
  }
  expect.fail('expected promise to be rejected')
}

describe('profileImageFetch', () => {
  describe('isPublicAddress', () => {
    const blocked = ['127.0.0.1', '10.0.0.1', '172.16.5.4', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1',
      '::1', '::', '::ffff:127.0.0.1', '::ffff:a9fe:a9fe', 'fe80::1', 'fd00:ec2::254', '64:ff9b::7f00:1', '2002:7f00:1::1', 'localhost']
    blocked.forEach(address => {
      it(`should block ${address}`, () => {
        expect(isPublicAddress(address)).to.equal(false)
      })
    })

    const allowed = ['8.8.8.8', '151.101.1.69', '2606:4700:4700::1111']
    allowed.forEach(address => {
      it(`should allow ${address}`, () => {
        expect(isPublicAddress(address)).to.equal(true)
      })
    })
  })

  describe('fetchProfileImage', () => {
    let server: http.Server
    let baseUrl: string
    let hits: string[]

    before((done) => {
      server = http.createServer((req, res) => {
        hits.push(req.url ?? '')
        if (req.url === '/redirect') {
          res.writeHead(302, { location: '/image.png' }).end()
        } else if (req.url === '/text') {
          res.writeHead(200, { 'content-type': 'text/plain' }).end('ami-id')
        } else if (req.url === '/huge') {
          res.writeHead(200, { 'content-type': 'image/png' }).end(Buffer.alloc(MAX_PROFILE_IMAGE_BYTES + 1))
        } else if (req.url === '/gzip') {
          res.writeHead(200, { 'content-type': 'image/png', 'content-encoding': 'gzip' }).end(Buffer.from([0x1f, 0x8b, 0x08]))
        } else if (req.url === '/missing') {
          res.writeHead(404, { 'content-type': 'image/png' }).end('nope')
        } else {
          res.writeHead(200, { 'content-type': 'image/png' }).end('PNGDATA')
        }
      })
      server.listen(0, '127.0.0.1', () => {
        baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
        done()
      })
    })

    beforeEach(() => {
      hits = []
    })

    after((done) => {
      server.close(done)
    })

    const allowLoopback = () => true

    it('should refuse loopback IP literals without connecting', async () => {
      await expectRejection(fetchProfileImage(`${baseUrl}/image.png`), /host is not allowed/)
      expect(hits).to.deep.equal([])
    })

    it('should refuse hostnames resolving to loopback without connecting', async () => {
      await expectRejection(fetchProfileImage(baseUrl.replace('127.0.0.1', 'localhost') + '/image.png'), /host is not allowed/)
      expect(hits).to.deep.equal([])
    })

    it('should refuse IPv4-mapped IPv6 loopback and cloud metadata addresses', async () => {
      await expectRejection(fetchProfileImage(baseUrl.replace('127.0.0.1', '[::ffff:127.0.0.1]') + '/image.png'), /host is not allowed/)
      await expectRejection(fetchProfileImage('http://169.254.169.254/latest/meta-data/'), /host is not allowed/)
      await expectRejection(fetchProfileImage('http://0xa9fea9fe/latest/meta-data/'), /host is not allowed/)
      expect(hits).to.deep.equal([])
    })

    it('should refuse non-http(s) schemes, credentials and relative URLs', async () => {
      await expectRejection(fetchProfileImage('file:///etc/passwd'), /must use http or https/)
      await expectRejection(fetchProfileImage('ftp://example.com/a.png'), /must use http or https/)
      await expectRejection(fetchProfileImage('http://user:pass@example.com/a.png'), /must not contain credentials/)
      await expectRejection(fetchProfileImage('example.com/a.png'), /not a valid absolute URL/)
    })

    it('should return the body of an allowed image response', async () => {
      const image = await fetchProfileImage(`${baseUrl}/image.png`, allowLoopback)
      expect(image.toString()).to.equal('PNGDATA')
    })

    it('should not follow redirects', async () => {
      await expectRejection(fetchProfileImage(`${baseUrl}/redirect`, allowLoopback), /status 302/)
      expect(hits).to.deep.equal(['/redirect'])
    })

    it('should reject non-image content types', async () => {
      await expectRejection(fetchProfileImage(`${baseUrl}/text`, allowLoopback), /did not return an image/)
    })

    it('should reject non-OK responses', async () => {
      await expectRejection(fetchProfileImage(`${baseUrl}/missing`, allowLoopback), /status 404/)
    })

    it('should reject content-encoded responses instead of saving undecoded bytes', async () => {
      await expectRejection(fetchProfileImage(`${baseUrl}/gzip`, allowLoopback), /encoded body/)
    })

    it('should reject responses larger than the size cap', async () => {
      await expectRejection(fetchProfileImage(`${baseUrl}/huge`, allowLoopback), /too large/)
    })
  })
})
