/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import http from 'node:http'
import { type AddressInfo } from 'node:net'
import chai from 'chai'
import { allowedHostsFromEnv, fetchProfileImage, isPublicAddress, type ProfileImageFetchOptions } from '../../lib/profileImageFetch'

const expect = chai.expect

async function rejectionOf (url: string, options?: ProfileImageFetchOptions) {
  try {
    const image = await fetchProfileImage(url, options)
    image.body.destroy()
  } catch (error) {
    return (error as Error).message
  }
  return expect.fail(`expected ${url} to be rejected`)
}

async function readAll (body: NodeJS.ReadableStream) {
  const chunks: Buffer[] = []
  for await (const chunk of body) chunks.push(chunk as Buffer)
  return Buffer.concat(chunks)
}

describe('profileImageFetch', () => {
  describe('isPublicAddress', () => {
    it('rejects loopback, private, link-local, CGNAT and reserved addresses', () => {
      for (const address of ['127.0.0.1', '10.0.0.1', '172.16.5.4', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255',
        '::', '::1', 'fd00::1', 'fe80::1', 'ff02::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:a9fe:a9fe', '64:ff9b::a9fe:a9fe', '2002:7f00:1::1', 'not-an-ip']) {
        expect(isPublicAddress(address), address).to.equal(false)
      }
    })

    it('accepts public addresses', () => {
      for (const address of ['8.8.8.8', '1.1.1.1', '151.101.1.69', '2606:4700:4700::1111', '2a00:1450:4001:82a::200e']) {
        expect(isPublicAddress(address), address).to.equal(true)
      }
    })
  })

  describe('allowedHostsFromEnv', () => {
    it('parses a comma-separated, case-insensitive host list', () => {
      expect(allowedHostsFromEnv(' Images.Example.com, cdn.example.org ,')).to.deep.equal(['images.example.com', 'cdn.example.org'])
      expect(allowedHostsFromEnv(undefined)).to.deep.equal([])
    })
  })

  describe('fetchProfileImage with the default policy', () => {
    it('rejects non-http schemes and unparsable urls', async () => {
      expect(await rejectionOf('file:///etc/passwd')).to.equal('only http(s) urls are allowed')
      expect(await rejectionOf('gopher://example.com/')).to.equal('only http(s) urls are allowed')
      expect(await rejectionOf('cataas.com/cat')).to.equal('invalid url')
    })

    it('rejects urls with credentials or non-default ports', async () => {
      expect(await rejectionOf('https://user:pass@example.com/a.png')).to.equal('urls with credentials are not allowed')
      expect(await rejectionOf('http://example.com:8080/a.png')).to.equal('port is not allowed')
    })

    it('rejects internal and metadata addresses', async () => {
      for (const url of ['http://127.0.0.1/', 'http://localhost/solve/challenges/server-side', 'http://169.254.169.254/latest/meta-data/',
        'http://10.0.0.1/', 'http://[::1]/', 'http://[::ffff:127.0.0.1]/', 'http://[fd00::1]/', 'http://2130706433/', 'http://0x7f.1/']) {
        expect(await rejectionOf(url), url).to.equal('url resolves to a non-public address')
      }
    })

    it('rejects hostnames when any resolved address is internal', async () => {
      const resolve = async () => [{ address: '93.184.215.14', family: 4 }, { address: '127.0.0.1', family: 4 }]
      expect(await rejectionOf('https://rebind.example/a.png', { resolve })).to.equal('url resolves to a non-public address')
    })

    it('rejects hosts outside a configured allowlist', async () => {
      expect(await rejectionOf('https://evil.example/a.png', { allowedHosts: ['images.example.com'] })).to.equal('host is not allowed')
    })
  })

  describe('fetchProfileImage against a local server', () => {
    let server: http.Server
    let port: number
    let options: ProfileImageFetchOptions
    const resolved: string[] = []
    let endlessClosed = () => {}

    before(async () => {
      server = http.createServer((req, res) => {
        if (req.url === '/cat.png') {
          res.writeHead(200, { 'Content-Type': 'image/png' }).end('png-bytes')
        } else if (req.url === '/redirect-public') {
          res.writeHead(302, { Location: '/cat.png' }).end()
        } else if (req.url === '/redirect-metadata') {
          res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' }).end()
        } else if (req.url === '/redirect-loop') {
          res.writeHead(302, { Location: '/redirect-loop' }).end()
        } else if (req.url === '/metadata.json') {
          res.writeHead(200, { 'Content-Type': 'application/json' }).end('{"secret":true}')
        } else if (req.url === '/huge.png') {
          const body = Buffer.alloc(6 * 1024 * 1024)
          res.writeHead(200, { 'Content-Type': 'image/png', 'Content-Length': body.length }).end(body)
        } else if (req.url === '/endless.png') {
          res.writeHead(200, { 'Content-Type': 'image/png', 'Transfer-Encoding': 'chunked' })
          const chunk = Buffer.alloc(64 * 1024)
          const timer = setInterval(() => res.write(chunk), 1)
          res.on('close', () => {
            clearInterval(timer)
            endlessClosed()
          })
        } else if (req.url === '/huge-chunked.png') {
          res.writeHead(200, { 'Content-Type': 'image/png', 'Transfer-Encoding': 'chunked' })
          for (let i = 0; i < 6; i++) res.write(Buffer.alloc(1024 * 1024))
          res.end()
        } else {
          res.writeHead(404).end()
        }
      })
      await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
      port = (server.address() as AddressInfo).port
      options = {
        allowedPorts: [String(port)],
        resolve: async (hostname) => {
          resolved.push(hostname)
          return [{ address: '127.0.0.1', family: 4 }]
        },
        isAllowedAddress: (address) => address === '127.0.0.1'
      }
    })

    after(() => {
      server.close()
    })

    it('connects to the validated address and streams the image', async () => {
      const image = await fetchProfileImage(`http://images.test:${port}/cat.png`, options)
      expect(image.extension).to.equal('png')
      expect((await readAll(image.body)).toString()).to.equal('png-bytes')
      expect(resolved).to.include('images.test')
    })

    it('connects to validated IPv6 literal addresses', async function () {
      const ipv6Server = http.createServer((_req, res) => res.writeHead(200, { 'Content-Type': 'image/gif' }).end('gif-bytes'))
      const listening = await new Promise<boolean>(resolve => {
        ipv6Server.once('error', () => { resolve(false) })
        ipv6Server.listen(0, '::1', () => { resolve(true) })
      })
      if (!listening) this.skip()
      try {
        const ipv6Port = (ipv6Server.address() as AddressInfo).port
        const image = await fetchProfileImage(`http://[::1]:${ipv6Port}/cat.gif`, { allowedPorts: [String(ipv6Port)], isAllowedAddress: (address) => address === '::1' })
        expect(image.extension).to.equal('gif')
        expect((await readAll(image.body)).toString()).to.equal('gif-bytes')
      } finally {
        ipv6Server.close()
      }
    })

    it('follows redirects that stay on allowed addresses', async () => {
      const image = await fetchProfileImage(`http://images.test:${port}/redirect-public`, options)
      expect((await readAll(image.body)).toString()).to.equal('png-bytes')
    })

    it('re-validates every redirect hop', async () => {
      expect(await rejectionOf(`http://images.test:${port}/redirect-metadata`, options)).to.equal('port is not allowed')
      expect(await rejectionOf(`http://images.test:${port}/redirect-metadata`, { ...options, allowedPorts: [String(port), ''] })).to.equal('url resolves to a non-public address')
      expect(await rejectionOf(`http://images.test:${port}/redirect-loop`, options)).to.equal('too many redirects')
    })

    it('rejects non-image responses and error statuses', async () => {
      expect(await rejectionOf(`http://images.test:${port}/metadata.json`, options)).to.equal('url did not return a supported image type')
      expect(await rejectionOf(`http://images.test:${port}/missing.png`, options)).to.equal('url returned status 404')
    })

    it('rejects images larger than the size limit', async () => {
      expect(await rejectionOf(`http://images.test:${port}/huge.png`, options)).to.equal('image is too large')
      const image = await fetchProfileImage(`http://images.test:${port}/huge-chunked.png`, options)
      try {
        await readAll(image.body)
        expect.fail('expected the size limit to abort the stream')
      } catch (error) {
        expect((error as Error).message).to.equal('image is too large')
      }
    })

    it('closes the source connection when the size limit is exceeded', async () => {
      const closed = new Promise<void>(resolve => { endlessClosed = resolve })
      const image = await fetchProfileImage(`http://images.test:${port}/endless.png`, options)
      try {
        await readAll(image.body)
        expect.fail('expected the size limit to abort the stream')
      } catch (error) {
        expect((error as Error).message).to.equal('image is too large')
      }
      await closed
    })

    it('applies the total timeout to hostname resolution', async () => {
      const started = Date.now()
      const message = await rejectionOf(`http://images.test:${port}/cat.png`, { ...options, timeoutMs: 50, resolve: async () => await new Promise(() => {}) })
      expect(message).to.match(/timeout/i)
      expect(Date.now() - started).to.be.below(2000)
    })
  })
})
