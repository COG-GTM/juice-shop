/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import http from 'node:http'
import { type AddressInfo } from 'node:net'
import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { Readable, Writable } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { fetchImage, isBlockedAddress, limitSize, profileImageUrlUpload } from '../../routes/profileImageUrlUpload'
import * as security from '../../lib/insecurity'
import { UserModel } from '../../models/user'

const expect = chai.expect
chai.use(sinonChai)

async function rejectionOf (promise: Promise<unknown>): Promise<Error> {
  try {
    await promise
  } catch (error) {
    return error as Error
  }
  throw new Error('expected promise to be rejected')
}

describe('profileImageUrlUpload', () => {
  describe('isBlockedAddress', () => {
    for (const address of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', '::', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1', '::ffff:7f00:1', 'not-an-ip']) {
      it(`blocks ${address}`, () => {
        expect(isBlockedAddress(address)).to.equal(true)
      })
    }

    for (const address of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) {
      it(`allows ${address}`, () => {
        expect(isBlockedAddress(address)).to.equal(false)
      })
    }
  })

  describe('fetchImage', () => {
    let server: http.Server
    let port: number
    let requests: number

    before((done) => {
      server = http.createServer((req, res) => {
        requests++
        res.writeHead(200, { 'Content-Type': 'image/png' })
        res.end('secret')
      })
      server.listen(0, '127.0.0.1', () => {
        port = (server.address() as AddressInfo).port
        done()
      })
    })

    beforeEach(() => {
      requests = 0
    })

    after((done) => {
      server.close(done)
    })

    for (const url of ['file:///etc/passwd', 'ftp://example.com/image.png', 'gopher://example.com/', 'cataas.com/cat']) {
      it(`rejects non-http(s) URL ${url}`, async () => {
        expect(await rejectionOf(fetchImage(url))).to.be.an('error')
      })
    }

    for (const url of ['http://169.254.169.254/latest/meta-data/', 'http://[::1]/', 'http://[::ffff:127.0.0.1]/', 'http://0.0.0.0/', 'http://2130706433/']) {
      it(`rejects internal IP literal ${url}`, async () => {
        expect((await rejectionOf(fetchImage(url))).message).to.match(/non-public address/)
      })
    }

    it('rejects loopback address without contacting the internal server', async () => {
      expect((await rejectionOf(fetchImage(`http://127.0.0.1:${port}/image.png`))).message).to.match(/non-public address/)
      expect(requests).to.equal(0)
    })

    it('rejects host names resolving to a loopback address without contacting the internal server', async () => {
      expect((await rejectionOf(fetchImage(`http://localhost:${port}/image.png`))).message).to.match(/non-public address/)
      expect(requests).to.equal(0)
    })
  })

  describe('limitSize', () => {
    const sink = () => new Writable({ write (_chunk, _encoding, callback) { callback() } })

    it('passes through data within the limit', async () => {
      await pipeline(Readable.from([Buffer.alloc(5), Buffer.alloc(5)]), limitSize(10), sink())
    })

    it('aborts once the limit is exceeded', async () => {
      const error = await rejectionOf(pipeline(Readable.from([Buffer.alloc(6), Buffer.alloc(6)]), limitSize(10), sink()))
      expect(error.message).to.match(/maximum size/)
    })
  })

  describe('route', () => {
    afterEach(() => {
      sinon.restore()
    })

    it('stores the URL as a plain link instead of fetching internal resources', async () => {
      const token = 'profileImageUrlUploadSpecToken'
      security.authenticatedUsers.put(token, { data: { id: 4711 } } as any)
      const update = sinon.stub().resolves()
      sinon.stub(UserModel, 'findByPk').resolves({ update } as any)
      const url = 'http://127.0.0.1:3000/rest/admin/application-configuration'
      const req: any = { body: { imageUrl: url }, cookies: { token }, app: { locals: {} }, socket: {} }
      const res: any = { location: sinon.spy(), redirect: sinon.spy() }
      const next = sinon.spy()

      await profileImageUrlUpload()(req, res, next)

      expect(update).to.have.been.calledOnceWith({ profileImage: url })
      expect(next).to.have.callCount(0)
      expect(res.redirect).to.have.callCount(1)
    })
  })
})
