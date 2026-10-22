/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import http from 'node:http'
import { type AddressInfo } from 'node:net'
import chai from 'chai'
import { fetchProfileImage, isPublicAddress, parseProfileImageUrl, ProfileImageFetchError } from '../../lib/profileImageFetch'
const expect = chai.expect

async function rejectionOf (promise: Promise<unknown>) {
  try {
    await promise
  } catch (error) {
    return error
  }
  throw new Error('expected promise to be rejected')
}

describe('profileImageFetch', () => {
  describe('isPublicAddress', () => {
    it('rejects loopback, private, link-local and other reserved addresses', () => {
      for (const address of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', '::', '::ffff:127.0.0.1', '::ffff:169.254.169.254', 'fd00::1', 'fe80::1', 'not-an-ip']) {
        expect(isPublicAddress(address), address).to.equal(false)
      }
    })

    it('accepts public addresses', () => {
      for (const address of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) {
        expect(isPublicAddress(address), address).to.equal(true)
      }
    })
  })

  describe('parseProfileImageUrl', () => {
    it('rejects non-string, relative, non-http(s) and credential-bearing URLs', () => {
      for (const url of [undefined, 42, 'cataas.com/cat', 'file:///etc/passwd', 'gopher://127.0.0.1:6379/_INFO', 'https://user:pass@example.com/a.png']) {
        expect(() => parseProfileImageUrl(url), String(url)).to.throw(ProfileImageFetchError)
      }
    })

    it('accepts absolute http and https URLs', () => {
      expect(parseProfileImageUrl('https://example.com/a.png').hostname).to.equal('example.com')
      expect(parseProfileImageUrl('http://example.com/a.png').protocol).to.equal('http:')
    })
  })

  describe('fetchProfileImage', () => {
    let server: http.Server
    let port: number
    let hits: string[]

    before((done) => {
      server = http.createServer((req, res) => {
        hits.push(req.url ?? '')
        if (req.url === '/redirect') {
          res.writeHead(302, { location: '/image.png' })
          res.end()
        } else {
          res.writeHead(200, { 'content-type': 'image/png' })
          res.end('png')
        }
      }).listen(0, '127.0.0.1', () => {
        port = (server.address() as AddressInfo).port
        done()
      })
    })

    beforeEach(() => { hits = [] })

    after((done) => { server.close(done) })

    it('never connects to loopback, private or metadata hosts', async () => {
      for (const url of [`http://127.0.0.1:${port}/image.png`, `http://localhost:${port}/image.png`, `http://[::1]:${port}/`, `http://[::ffff:127.0.0.1]:${port}/`, `http://2130706433:${port}/`, `http://0x7f.1:${port}/`, 'http://169.254.169.254/latest/meta-data/']) {
        expect(await rejectionOf(fetchProfileImage(url)), url).to.be.instanceOf(ProfileImageFetchError)
      }
      expect(hits).to.deep.equal([])
    })

    it('connects to the vetted address and returns the image stream', async () => {
      const response = await fetchProfileImage(`http://localhost:${port}/image.png?size=1`, () => true)
      let body = ''
      for await (const chunk of response) body += String(chunk)
      expect(body).to.equal('png')
      expect(hits).to.deep.equal(['/image.png?size=1'])
    })

    it('does not follow redirects', async () => {
      const error = await rejectionOf(fetchProfileImage(`http://127.0.0.1:${port}/redirect`, () => true))
      expect(error).to.be.instanceOf(ProfileImageFetchError)
      expect(hits).to.deep.equal(['/redirect'])
    })
  })
})
