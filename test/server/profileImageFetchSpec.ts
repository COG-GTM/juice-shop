/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import http from 'node:http'
import { type AddressInfo } from 'node:net'
import { fetchProfileImage, isPublicAddress, parseProfileImageUrl, ProfileImageFetchError, MAX_PROFILE_IMAGE_BYTES } from '../../lib/profileImageFetch'

const expect = chai.expect

const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d])
const allowAll = () => true

async function expectRejection (promise: Promise<unknown>, message: RegExp) {
  try {
    await promise
  } catch (error) {
    expect(error).to.be.instanceOf(ProfileImageFetchError)
    expect((error as Error).message).to.match(message)
    return
  }
  expect.fail('expected the profile image fetch to be rejected')
}

describe('profileImageFetch', () => {
  let server: http.Server
  let baseUrl: string
  let hits: string[]
  let handler: (req: http.IncomingMessage, res: http.ServerResponse) => void

  before((done) => {
    server = http.createServer((req, res) => {
      hits.push(req.url ?? '')
      handler(req, res)
    })
    server.listen(0, '127.0.0.1', () => {
      baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
      done()
    })
  })

  after((done) => {
    server.close(() => { done() })
  })

  beforeEach(() => {
    hits = []
    handler = (req, res) => { res.writeHead(200, { 'content-type': 'image/png' }).end(PNG) }
  })

  describe('isPublicAddress', () => {
    it('blocks loopback, private, link-local, CGNAT and IPv4-mapped IPv6 addresses', () => {
      for (const address of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', '::', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1', '::ffff:169.254.169.254']) {
        expect(isPublicAddress(address), address).to.equal(false)
      }
    })

    it('allows public addresses', () => {
      for (const address of ['8.8.8.8', '151.101.1.140', '2606:4700:4700::1111']) {
        expect(isPublicAddress(address), address).to.equal(true)
      }
    })

    it('rejects values that are not IP addresses', () => {
      expect(isPublicAddress('localhost')).to.equal(false)
    })
  })

  describe('parseProfileImageUrl', () => {
    it('rejects non-http(s) schemes', () => {
      for (const url of ['file:///etc/passwd', 'gopher://127.0.0.1:6379/_INFO', 'ftp://example.com/a.png', 'data:image/png;base64,AAAA', 'javascript:alert(1)']) {
        expect(() => parseProfileImageUrl(url), url).to.throw(ProfileImageFetchError)
      }
    })

    it('rejects relative URLs, embedded credentials and non-string input', () => {
      expect(() => parseProfileImageUrl('cataas.com/cat')).to.throw(ProfileImageFetchError)
      expect(() => parseProfileImageUrl('https://user:pass@example.com/a.png')).to.throw(ProfileImageFetchError)
      expect(() => parseProfileImageUrl(['https://example.com/a.png'])).to.throw(ProfileImageFetchError)
    })

    it('rejects CSP payloads that are not valid URLs', () => {
      expect(() => parseProfileImageUrl("https://a.png; script-src 'unsafe-inline' 'self' 'unsafe-eval'")).to.throw(ProfileImageFetchError)
    })
  })

  describe('fetchProfileImage', () => {
    it('does not connect to loopback or metadata IP literals', async () => {
      await expectRejection(fetchProfileImage(`${baseUrl}/latest/meta-data/`), /not allowed/)
      await expectRejection(fetchProfileImage('http://169.254.169.254/latest/meta-data/iam/security-credentials/'), /not allowed/)
      await expectRejection(fetchProfileImage(`http://[::ffff:127.0.0.1]:${(server.address() as AddressInfo).port}/`), /not allowed/)
      expect(hits).to.deep.equal([])
    })

    it('does not connect to host names resolving to internal addresses', async () => {
      await expectRejection(fetchProfileImage(`http://localhost:${(server.address() as AddressInfo).port}/solve/challenges/server-side`), /not allowed/)
      expect(hits).to.deep.equal([])
    })

    it('returns the image and an extension derived from the content type', async () => {
      const image = await fetchProfileImage(`${baseUrl}/avatar.svg`, allowAll)
      expect(image.extension).to.equal('png')
      expect(image.data.equals(PNG)).to.equal(true)
    })

    it('does not follow redirects', async () => {
      handler = (req, res) => { res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data/' }).end() }
      await expectRejection(fetchProfileImage(`${baseUrl}/redirect.png`, allowAll), /status 302/)
      expect(hits).to.deep.equal(['/redirect.png'])
    })

    it('rejects non-image responses', async () => {
      handler = (req, res) => { res.writeHead(200, { 'content-type': 'application/json' }).end('{"AccessKeyId":"AKIA"}') }
      await expectRejection(fetchProfileImage(`${baseUrl}/creds.png`, allowAll), /did not return an image/)
    })

    it('rejects SVG and other unsupported image types', async () => {
      handler = (req, res) => { res.writeHead(200, { 'content-type': 'image/svg+xml' }).end('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>') }
      await expectRejection(fetchProfileImage(`${baseUrl}/a.svg`, allowAll), /JPEG, PNG or GIF/)
    })

    it('rejects bodies whose bytes do not match the declared image type', async () => {
      handler = (req, res) => { res.writeHead(200, { 'content-type': 'image/png' }).end('root:x:0:0:root:/root:/bin/bash') }
      await expectRejection(fetchProfileImage(`${baseUrl}/passwd.png`, allowAll), /does not match/)
    })

    it('rejects responses larger than the size limit', async () => {
      handler = (req, res) => {
        res.writeHead(200, { 'content-type': 'image/png' })
        res.end(Buffer.concat([PNG, Buffer.alloc(MAX_PROFILE_IMAGE_BYTES)]))
      }
      await expectRejection(fetchProfileImage(`${baseUrl}/huge.png`, allowAll), /too large/)
    })

    it('rejects non-OK responses', async () => {
      handler = (req, res) => { res.writeHead(404, { 'content-type': 'image/png' }).end(PNG) }
      await expectRejection(fetchProfileImage(`${baseUrl}/missing.png`, allowAll), /status 404/)
    })
  })
})
