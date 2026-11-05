/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import http from 'node:http'
import { type AddressInfo } from 'node:net'
import { fetchProfileImage, isPublicAddress, MAX_PROFILE_IMAGE_BYTES, ProfileImageFetchError } from '../../routes/profileImageUrlUpload'

const expect = chai.expect

const png = Buffer.from('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d49444154789c6360000002000154a24f5d0000000049454e44ae426082', 'hex')
const svg = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>')

async function expectRejected (promise: Promise<unknown>, message: RegExp) {
  try {
    await promise
  } catch (error) {
    expect(error).to.be.instanceOf(ProfileImageFetchError)
    expect((error as Error).message).to.match(message)
    return
  }
  expect.fail('expected the profile image fetch to be rejected')
}

describe('profileImageUrlUpload', () => {
  let server: http.Server
  let baseUrl: string
  let hits: string[]
  const onlyLocalTestServer = (address: string) => address === '127.0.0.1'

  before((done) => {
    server = http.createServer((req, res) => {
      hits.push(req.url ?? '')
      switch (req.url) {
        case '/image.svg':
          res.writeHead(200, { 'content-type': 'image/png' }).end(png)
          break
        case '/evil.png':
          res.writeHead(200, { 'content-type': 'image/png' }).end(svg)
          break
        case '/huge.png':
          res.writeHead(200, { 'content-type': 'image/png' }).end(Buffer.concat([png, Buffer.alloc(MAX_PROFILE_IMAGE_BYTES)]))
          break
        case '/redirect-public':
          res.writeHead(302, { location: '/image.svg' }).end()
          break
        case '/redirect-metadata':
          res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data/' }).end()
          break
        case '/redirect-loopback':
          res.writeHead(302, { location: `http://127.0.0.2:${(server.address() as AddressInfo).port}/image.svg` }).end()
          break
        default:
          res.writeHead(404).end()
      }
    }).listen(0, '127.0.0.1', () => {
      baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
      done()
    })
  })

  after((done) => { server.close(done) })

  beforeEach(() => { hits = [] })

  describe('isPublicAddress', () => {
    it('rejects loopback, private, link-local and mapped addresses', () => {
      for (const address of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '0.0.0.0', '::1', '::', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1', '::ffff:7f00:1', 'not-an-ip']) {
        expect(isPublicAddress(address), address).to.equal(false)
      }
    })

    it('accepts public addresses', () => {
      for (const address of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) {
        expect(isPublicAddress(address), address).to.equal(true)
      }
    })
  })

  describe('fetchProfileImage', () => {
    it('rejects non-http(s) and malformed URLs', async () => {
      await expectRejected(fetchProfileImage('data:image/svg+xml,<svg onload="alert(1)"/>#.svg'), /http or https/)
      await expectRejected(fetchProfileImage('file:///etc/passwd'), /http or https/)
      await expectRejected(fetchProfileImage('ftp://example.com/a.png'), /http or https/)
      await expectRejected(fetchProfileImage('cataas.com/cat'), /valid absolute URL/)
      await expectRejected(fetchProfileImage(['http://example.com/a.png']), /must be a string/)
    })

    it('rejects internal IP literals without connecting', async () => {
      for (const url of [
        `${baseUrl}/image.svg`,
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/role',
        'http://[::1]:3000/rest/admin/application-version',
        'http://[::ffff:127.0.0.1]:3000/',
        'http://0x7f000001:3000/',
        'http://2130706433:3000/'
      ]) {
        await expectRejected(fetchProfileImage(url), /host is not allowed/)
      }
      expect(hits).to.deep.equal([])
    })

    it('rejects hostnames that resolve to internal addresses', async () => {
      await expectRejected(fetchProfileImage(`http://localhost:${(server.address() as AddressInfo).port}/image.svg`), /host is not allowed/)
      expect(hits).to.deep.equal([])
    })

    it('re-checks the destination of every redirect', async () => {
      await expectRejected(fetchProfileImage(`${baseUrl}/redirect-metadata`, onlyLocalTestServer), /host is not allowed/)
      await expectRejected(fetchProfileImage(`${baseUrl}/redirect-loopback`, onlyLocalTestServer), /host is not allowed/)
      expect(hits).to.deep.equal(['/redirect-metadata', '/redirect-loopback'])
    })

    it('rejects SVG content regardless of the URL extension or content type', async () => {
      await expectRejected(fetchProfileImage(`${baseUrl}/evil.png`, onlyLocalTestServer), /JPEG, PNG, GIF or WebP/)
    })

    it('rejects responses larger than the size limit', async () => {
      await expectRejected(fetchProfileImage(`${baseUrl}/huge.png`, onlyLocalTestServer), /too large/)
    })

    it('derives the extension from the detected image type, not the URL', async () => {
      const image = await fetchProfileImage(`${baseUrl}/image.svg`, onlyLocalTestServer)
      expect(image.extension).to.equal('png')
      expect(image.data.equals(png)).to.equal(true)
    })

    it('follows redirects to allowed hosts', async () => {
      const image = await fetchProfileImage(`${baseUrl}/redirect-public`, onlyLocalTestServer)
      expect(image.extension).to.equal('png')
      expect(hits).to.deep.equal(['/redirect-public', '/image.svg'])
    })
  })
})
