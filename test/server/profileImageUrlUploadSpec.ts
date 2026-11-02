/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import http from 'node:http'
import { type AddressInfo } from 'node:net'
import { fetchProfileImage, isPublicAddress, ProfileImageFetchError, MAX_PROFILE_IMAGE_BYTES } from '../../routes/profileImageUrlUpload'

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

function startServer (host: string, handler: http.RequestListener): Promise<{ server: http.Server, url: string }> {
  return new Promise((resolve) => {
    const server = http.createServer(handler)
    server.listen(0, host, () => { resolve({ server, url: `http://${host}:${(server.address() as AddressInfo).port}` }) })
  })
}

describe('profileImageUrlUpload', () => {
  describe('isPublicAddress', () => {
    it('should block loopback, private, link-local, CGNAT and IPv4-mapped addresses', () => {
      for (const address of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', '::', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1', '::ffff:169.254.169.254', 'localhost']) {
        expect(isPublicAddress(address), address).to.equal(false)
      }
    })

    it('should allow public addresses', () => {
      for (const address of ['93.184.216.34', '8.8.8.8', '2606:4700:4700::1111']) {
        expect(isPublicAddress(address), address).to.equal(true)
      }
    })
  })

  describe('fetchProfileImage', () => {
    let internal: { server: http.Server, url: string }
    let external: { server: http.Server, url: string }
    let internalHits: string[]
    let dripClosed: Promise<void>
    const onlyExternal = (address: string) => address === '127.0.0.1'

    before(async () => {
      internal = await startServer('127.0.0.2', (req, res) => {
        internalHits.push(req.url ?? '')
        res.writeHead(200, { 'content-type': 'image/png' })
        res.end(png)
      })
      const routes: Record<string, [number, http.OutgoingHttpHeaders, string | Buffer]> = {
        '/image.png': [200, { 'content-type': 'image/png' }, png],
        '/hop.png': [302, { location: '/image.png' }, ''],
        '/to-internal.png': [302, { location: `${internal.url}/latest/meta-data/` }, ''],
        '/to-file.png': [302, { location: 'file:///etc/passwd' }, ''],
        '/loop.png': [302, { location: '/loop.png' }, ''],
        '/text': [200, { 'content-type': 'text/plain' }, 'AccessKeyId=SECRET'],
        '/disguised.jpg': [200, { 'content-type': 'image/jpeg' }, 'AccessKeyId=SECRET'],
        '/svg': [200, { 'content-type': 'image/svg+xml' }, '<svg xmlns="http://www.w3.org/2000/svg"/>'],
        '/huge.png': [200, { 'content-type': 'image/png' }, Buffer.concat([png, Buffer.alloc(MAX_PROFILE_IMAGE_BYTES)])]
      }
      external = await startServer('127.0.0.1', (req, res) => {
        if (req.url === '/drip-hop.png') {
          res.writeHead(302, { location: '/image.png' })
          const drip = setInterval(() => res.write('x'), 20)
          dripClosed = new Promise((resolve) => res.on('close', () => { clearInterval(drip); resolve() }))
          return
        }
        const [status, headers, body] = routes[req.url ?? ''] ?? [404, {}, '']
        res.writeHead(status, headers)
        res.end(body)
      })
    })

    beforeEach(() => { internalHits = [] })

    after(() => {
      internal.server.close()
      external.server.close()
    })

    it('should reject non-http(s) schemes, credentials and relative URLs', async () => {
      for (const url of ['file:///etc/passwd', 'gopher://127.0.0.1:6379/_INFO', 'ftp://example.com/a.png', 'data:image/png;base64,AAAA', 'https://user:pass@example.com/a.png', 'cataas.com/cat', 42]) {
        await expectRejected(fetchProfileImage(url), /must use http or https|credentials|not a valid|must be a string/)
      }
    })

    it('should reject loopback, metadata and private addresses without connecting', async () => {
      for (const url of [`${internal.url}/`, 'http://127.0.0.1:3000/', 'http://169.254.169.254/latest/meta-data/', 'https://169.254.169.254/', 'http://[::1]/', 'http://[::ffff:127.0.0.1]/', 'http://10.0.0.1/', 'http://0x7f000001/', 'http://2130706433/']) {
        await expectRejected(fetchProfileImage(url), /not allowed/)
      }
      expect(internalHits).to.deep.equal([])
    })

    it('should reject hostnames that resolve to internal addresses', async () => {
      await expectRejected(fetchProfileImage(external.url.replace('127.0.0.1', 'localhost') + '/image.png'), /not allowed/)
    })

    it('should return a verified image from an allowed host, following safe redirects', async () => {
      const image = await fetchProfileImage(`${external.url}/hop.png`, onlyExternal)
      expect(image.extension).to.equal('png')
      expect(image.data.equals(png)).to.equal(true)
    })

    it('should close redirect responses instead of draining their bodies', async () => {
      const image = await fetchProfileImage(`${external.url}/drip-hop.png`, onlyExternal)
      expect(image.extension).to.equal('png')
      await dripClosed
    })

    it('should re-check the target of every redirect', async () => {
      await expectRejected(fetchProfileImage(`${external.url}/to-internal.png`, onlyExternal), /not allowed/)
      await expectRejected(fetchProfileImage(`${external.url}/to-file.png`, onlyExternal), /must use http or https/)
      await expectRejected(fetchProfileImage(`${external.url}/loop.png`, onlyExternal), /too many times/)
      expect(internalHits).to.deep.equal([])
    })

    it('should reject non-image responses, disguised content, SVG and oversized bodies', async () => {
      await expectRejected(fetchProfileImage(`${external.url}/text`, onlyExternal), /did not return an image/)
      await expectRejected(fetchProfileImage(`${external.url}/disguised.jpg`, onlyExternal), /does not match/)
      await expectRejected(fetchProfileImage(`${external.url}/svg`, onlyExternal), /JPEG, PNG or GIF/)
      await expectRejected(fetchProfileImage(`${external.url}/huge.png`, onlyExternal), /too large/)
      await expectRejected(fetchProfileImage(`${external.url}/missing.png`, onlyExternal), /status 404/)
    })
  })
})
