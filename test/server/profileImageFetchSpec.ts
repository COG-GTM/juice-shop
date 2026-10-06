/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import http, { type Server } from 'node:http'
import { type AddressInfo } from 'node:net'
import { fetchProfileImage, isPublicAddress, ProfileImageUrlError } from '../../lib/profileImageFetch'

const expect = chai.expect

async function expectRejection (promise: Promise<unknown>, message = '') {
  let error: unknown
  try {
    await promise
  } catch (e) {
    error = e
  }
  expect(error).to.be.instanceOf(ProfileImageUrlError)
  expect((error as Error).message).to.include(message)
}

async function readAll (body: NodeJS.ReadableStream) {
  const chunks: Buffer[] = []
  for await (const chunk of body) chunks.push(Buffer.from(chunk as Buffer))
  return Buffer.concat(chunks).toString()
}

describe('profileImageFetch', () => {
  let server: Server
  let port: string
  let requests: string[]
  const loopbackOnly = { isAllowedAddress: (address: string) => address === '127.0.0.1' }

  before((done) => {
    server = http.createServer((req, res) => {
      requests.push(req.url ?? '')
      if (req.url === '/image.png') {
        res.writeHead(200, { 'content-type': 'image/png' })
        res.end('PNGDATA')
      } else if (req.url === '/metadata') {
        res.writeHead(200, { 'content-type': 'text/plain' })
        res.end('AccessKeyId=SECRET')
      } else if (req.url === '/redirect-internal') {
        res.writeHead(302, { location: 'http://internal.test/latest/meta-data/' })
        res.end()
      } else if (req.url === '/redirect-metadata') {
        res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data/' })
        res.end()
      } else if (req.url === '/redirect-image') {
        res.writeHead(301, { location: '/image.png' })
        res.end()
      } else {
        res.writeHead(404)
        res.end()
      }
    })
    server.listen(0, '127.0.0.1', () => {
      port = String((server.address() as AddressInfo).port)
      done()
    })
  })

  beforeEach(() => {
    requests = []
  })

  after((done) => {
    server.close(done)
  })

  describe('isPublicAddress', () => {
    for (const address of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', '::', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1', '::ffff:169.254.169.254', 'not-an-ip']) {
      it(`rejects ${address}`, () => {
        expect(isPublicAddress(address)).to.equal(false)
      })
    }

    for (const address of ['93.184.216.34', '8.8.8.8', '2606:4700:4700::1111']) {
      it(`accepts ${address}`, () => {
        expect(isPublicAddress(address)).to.equal(true)
      })
    }
  })

  it('rejects a loopback url without sending a request', async () => {
    await expectRejection(fetchProfileImage(`http://127.0.0.1:${port}/metadata`, { allowedPorts: [port] }), 'non-public')
    expect(requests).to.deep.equal([])
  })

  it('rejects the cloud metadata endpoint', async () => {
    await expectRejection(fetchProfileImage('http://169.254.169.254/latest/meta-data/iam/security-credentials/'), 'non-public')
  })

  it('rejects hostnames that resolve to a private address', async () => {
    const resolve = async () => [{ address: '10.0.0.5', family: 4 }]
    await expectRejection(fetchProfileImage('http://images.example/cat.jpg', { resolve }), 'non-public')
  })

  it('rejects hostnames when any resolved address is private', async () => {
    const resolve = async () => [{ address: '93.184.216.34', family: 4 }, { address: '127.0.0.1', family: 4 }]
    await expectRejection(fetchProfileImage('http://images.example/cat.jpg', { resolve }), 'non-public')
  })

  for (const url of ['file:///etc/passwd', 'ftp://example.com/a.png', 'gopher://127.0.0.1:6379/_INFO', 'data:image/png;base64,AAAA', 'cataas.com/cat']) {
    it(`rejects ${url}`, async () => {
      await expectRejection(fetchProfileImage(url))
    })
  }

  it('rejects urls with embedded credentials', async () => {
    await expectRejection(fetchProfileImage('http://user:pass@example.com/a.png'), 'credentials')
  })

  it('rejects non-default ports', async () => {
    await expectRejection(fetchProfileImage('http://example.com:6379/a.png'), 'port')
  })

  it('fetches an image from an allowed address', async () => {
    const image = await fetchProfileImage(`http://127.0.0.1:${port}/image.png`, { ...loopbackOnly, allowedPorts: [port] })
    expect(image.extension).to.equal('png')
    expect(await readAll(image.body)).to.equal('PNGDATA')
  })

  it('pins the connection to the vetted address', async () => {
    const resolve = async () => [{ address: '127.0.0.1', family: 4 }]
    const image = await fetchProfileImage(`http://images.example:${port}/image.png`, { ...loopbackOnly, resolve, allowedPorts: [port] })
    expect(await readAll(image.body)).to.equal('PNGDATA')
  })

  it('rejects responses that are not images', async () => {
    await expectRejection(fetchProfileImage(`http://127.0.0.1:${port}/metadata`, { ...loopbackOnly, allowedPorts: [port] }), 'image type')
  })

  it('follows redirects to allowed addresses', async () => {
    const image = await fetchProfileImage(`http://127.0.0.1:${port}/redirect-image`, { ...loopbackOnly, allowedPorts: [port] })
    expect(image.extension).to.equal('png')
  })

  it('re-validates redirect targets by literal address', async () => {
    await expectRejection(fetchProfileImage(`http://127.0.0.1:${port}/redirect-metadata`, { ...loopbackOnly, allowedPorts: [port, ''] }), 'non-public')
    expect(requests).to.deep.equal(['/redirect-metadata'])
  })

  it('re-validates redirect targets by resolved hostname', async () => {
    const resolve = async () => [{ address: '10.0.0.5', family: 4 }]
    await expectRejection(fetchProfileImage(`http://127.0.0.1:${port}/redirect-internal`, { ...loopbackOnly, resolve, allowedPorts: [port, ''] }), 'non-public')
  })
})
