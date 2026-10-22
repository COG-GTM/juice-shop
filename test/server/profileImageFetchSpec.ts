/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import http from 'node:http'
import { type AddressInfo } from 'node:net'
import { fetchProfileImage, isPublicAddress, parseProfileImageUrl, ProfileImageFetchError, MAX_PROFILE_IMAGE_BYTES } from '../../lib/profileImageFetch'

const expect = chai.expect

const png = Buffer.from('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d4944415478da63f8ffff3f0005fe02fea7d6a4b60000000049454e44ae426082', 'hex')

async function expectRejected (promise: Promise<unknown>, message: RegExp) {
  try {
    await promise
  } catch (error) {
    expect(error).to.be.instanceOf(ProfileImageFetchError)
    expect((error as Error).message).to.match(message)
    return
  }
  expect.fail('expected fetchProfileImage to reject')
}

describe('profileImageFetch', () => {
  describe('isPublicAddress', () => {
    it('blocks loopback, private, link-local, CGNAT and IPv4-mapped addresses', () => {
      for (const address of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', '::', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1', '::ffff:169.254.169.254', 'localhost']) {
        expect(isPublicAddress(address), address).to.equal(false)
      }
    })

    it('allows public addresses', () => {
      for (const address of ['93.184.216.34', '8.8.8.8', '2606:4700:4700::1111']) {
        expect(isPublicAddress(address), address).to.equal(true)
      }
    })
  })

  describe('parseProfileImageUrl', () => {
    it('rejects non-http(s) schemes, credentials, relative URLs and non-strings', () => {
      for (const url of ['file:///etc/passwd', 'gopher://127.0.0.1:6379/_INFO', 'ftp://example.com/a.png', 'data:image/png;base64,AAAA', 'http://user:pass@example.com/a.png', 'cataas.com/cat', 42]) {
        expect(() => parseProfileImageUrl(url), String(url)).to.throw(ProfileImageFetchError)
      }
    })

    it('accepts absolute http(s) URLs', () => {
      expect(parseProfileImageUrl('https://example.com/a.png').hostname).to.equal('example.com')
    })
  })

  describe('fetchProfileImage', () => {
    let server: http.Server
    let baseUrl: string
    let hits: string[]

    before((done) => {
      const routes: Record<string, [number, http.OutgoingHttpHeaders, string | Buffer]> = {
        '/image.png': [200, { 'content-type': 'image/png' }, png],
        '/latest/meta-data/iam/security-credentials/role': [200, { 'content-type': 'text/plain' }, 'AccessKeyId=SECRET'],
        '/disguised.jpg': [200, { 'content-type': 'image/jpeg' }, 'AccessKeyId=SECRET'],
        '/svg': [200, { 'content-type': 'image/svg+xml' }, '<svg xmlns="http://www.w3.org/2000/svg"/>'],
        '/redirect.png': [302, { location: '/latest/meta-data/iam/security-credentials/role' }, ''],
        '/huge.png': [200, { 'content-type': 'image/png' }, Buffer.concat([png, Buffer.alloc(MAX_PROFILE_IMAGE_BYTES)])]
      }
      server = http.createServer((req, res) => {
        hits.push(req.url ?? '')
        const [status, headers, body] = routes[req.url ?? ''] ?? [404, {}, '']
        res.writeHead(status, headers)
        res.end(body)
      })
      server.listen(0, '127.0.0.1', () => {
        baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
        done()
      })
    })

    beforeEach(() => { hits = [] })

    after((done) => { server.close(done) })

    it('refuses loopback, metadata and private IP literals without connecting', async () => {
      for (const url of [`${baseUrl}/image.png`, 'http://169.254.169.254/latest/meta-data/', 'http://[::1]/', 'http://[::ffff:127.0.0.1]/', 'http://10.0.0.1/', 'http://0x7f000001/', 'http://2130706433/']) {
        await expectRejected(fetchProfileImage(url), /not allowed/)
      }
      expect(hits).to.deep.equal([])
    })

    it('refuses hostnames that resolve to internal addresses', async () => {
      await expectRejected(fetchProfileImage(baseUrl.replace('127.0.0.1', 'localhost') + '/image.png'), /not allowed/)
      expect(hits).to.deep.equal([])
    })

    it('returns a verified image from an allowed host', async () => {
      const image = await fetchProfileImage(`${baseUrl}/image.png`, () => true)
      expect(image.extension).to.equal('png')
      expect(image.data.equals(png)).to.equal(true)
    })

    it('does not follow redirects', async () => {
      await expectRejected(fetchProfileImage(`${baseUrl}/redirect.png`, () => true), /status 302/)
      expect(hits).to.deep.equal(['/redirect.png'])
    })

    it('rejects non-image responses, disguised content, SVG and oversized bodies', async () => {
      await expectRejected(fetchProfileImage(`${baseUrl}/latest/meta-data/iam/security-credentials/role`, () => true), /did not return an image/)
      await expectRejected(fetchProfileImage(`${baseUrl}/disguised.jpg`, () => true), /does not match/)
      await expectRejected(fetchProfileImage(`${baseUrl}/svg`, () => true), /JPEG, PNG or GIF/)
      await expectRejected(fetchProfileImage(`${baseUrl}/huge.png`, () => true), /too large/)
      await expectRejected(fetchProfileImage(`${baseUrl}/missing.png`, () => true), /status 404/)
    })
  })
})
