/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import http from 'node:http'
import { type AddressInfo } from 'node:net'
import chai from 'chai'
import { fetchPublicImage, isDeniedAddress, parseImageUrl } from '../../lib/safeImageFetch'

const expect = chai.expect

async function rejectionOf (promise: Promise<unknown>): Promise<Error> {
  try {
    await promise
  } catch (error) {
    return error as Error
  }
  throw new Error('expected promise to be rejected')
}

describe('safeImageFetch', () => {
  describe('isDeniedAddress', () => {
    it('denies loopback, private, link-local and metadata addresses', () => {
      for (const address of ['127.0.0.1', '127.1.2.3', '10.0.0.1', '172.16.5.4', '192.168.0.1', '169.254.169.254',
        '100.64.0.1', '0.0.0.0', '255.255.255.255', '::1', '::', 'fd00::1', 'fe80::1%eth0', 'ff02::1',
        '::ffff:127.0.0.1', '::ffff:a9fe:a9fe', '64:ff9b::a9fe:a9fe', '2002:a9fe:a9fe::1', '[::1]']) {
        expect(isDeniedAddress(address), address).to.equal(true)
      }
    })

    it('denies anything that is not an IP address', () => {
      expect(isDeniedAddress('localhost')).to.equal(true)
      expect(isDeniedAddress('')).to.equal(true)
    })

    it('allows public addresses', () => {
      for (const address of ['1.1.1.1', '8.8.8.8', '172.32.0.1', '2606:4700:4700::1111', '::ffff:8.8.8.8']) {
        expect(isDeniedAddress(address), address).to.equal(false)
      }
    })
  })

  describe('parseImageUrl', () => {
    it('accepts http and https URLs of public hosts', () => {
      expect(parseImageUrl('https://example.com/cat.png').hostname).to.equal('example.com')
      expect(parseImageUrl('http://8.8.8.8/cat.png').hostname).to.equal('8.8.8.8')
    })

    it('rejects other protocols', () => {
      for (const url of ['file:///etc/passwd', 'gopher://localhost:6379/_INFO', 'ftp://example.com/cat.png', 'data:image/png;base64,AAAA']) {
        expect(() => parseImageUrl(url), url).to.throw('unsupported protocol')
      }
    })

    it('rejects IP literals of non-public addresses in any notation', () => {
      for (const url of ['http://169.254.169.254/latest/meta-data/', 'http://127.0.0.1:3000/', 'http://2130706433/', 'http://0x7f.1/', 'http://[::1]/', 'http://[::ffff:169.254.169.254]/']) {
        expect(() => parseImageUrl(url), url).to.throw('non-public address')
      }
    })

    it('rejects URLs with credentials and malformed URLs', () => {
      expect(() => parseImageUrl('https://user:pass@example.com/cat.png')).to.throw('credentials')
      expect(() => parseImageUrl('cataas.com/cat')).to.throw('not a valid URL')
      expect(() => parseImageUrl(undefined)).to.throw('not a valid URL')
    })
  })

  describe('fetchPublicImage', () => {
    let server: http.Server
    let port: number
    let requests: number

    before((done) => {
      requests = 0
      server = http.createServer((req, res) => {
        requests++
        res.writeHead(200, { 'Content-Type': 'image/png' })
        res.end('internal secret')
      })
      server.listen(0, '127.0.0.1', () => {
        port = (server.address() as AddressInfo).port
        done()
      })
    })

    after((done) => {
      server.close(done)
    })

    it('never connects to services on the server itself', async () => {
      for (const url of [`http://localhost:${port}/`, `http://127.0.0.1:${port}/`, `http://[::ffff:127.0.0.1]:${port}/`, `http://2130706433:${port}/`]) {
        const error = await rejectionOf(fetchPublicImage(url))
        expect(error.message, url).to.contain('non-public address')
      }
      expect(requests).to.equal(0)
    })

    it('never connects to the cloud metadata service', async () => {
      const error = await rejectionOf(fetchPublicImage('http://169.254.169.254/latest/meta-data/iam/security-credentials/'))
      expect(error.message).to.contain('non-public address')
    })
  })
})
