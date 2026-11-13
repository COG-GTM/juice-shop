/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import sinon from 'sinon'
import http from 'node:http'
import { type AddressInfo } from 'node:net'
import * as security from '../../lib/insecurity'
import { UserModel } from '../../models/user'
import { fetchExternalImage, isBlockedAddress, profileImageUrlUpload } from '../../routes/profileImageUrlUpload'

const expect = chai.expect

describe('profileImageUrlUpload', () => {
  let server: http.Server
  let port: number
  let hits: number

  before((done) => {
    hits = 0
    server = http.createServer((req, res) => {
      hits++
      res.end('internal')
    }).listen(0, '127.0.0.1', () => {
      port = (server.address() as AddressInfo).port
      done()
    })
  })

  after((done) => {
    server.close(done)
  })

  beforeEach(() => {
    hits = 0
  })

  it('should not let the profile image URL upload make the server request an internal URL', async () => {
    const update = sinon.stub().resolves()
    const findByPk = sinon.stub(UserModel, 'findByPk').resolves({ update } as any)
    security.authenticatedUsers.put('ssrf-test-token', { data: { id: 4711 } } as any)
    const imageUrl = `http://127.0.0.1:${port}/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3`
    const req: any = { body: { imageUrl }, cookies: { token: 'ssrf-test-token' }, app: { locals: {} }, socket: {} }
    const res: any = { location: sinon.spy(), redirect: sinon.spy() }
    const next = sinon.spy()
    try {
      await profileImageUrlUpload()(req, res, next)
    } finally {
      findByPk.restore()
    }
    expect(hits).to.equal(0)
    expect(update.calledWith({ profileImage: imageUrl })).to.equal(true)
    expect(res.redirect.calledOnce).to.equal(true)
  })

  describe('should block requests to internal destinations', () => {
    const targets = [
      (port: number) => `http://127.0.0.1:${port}/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3`,
      (port: number) => `http://localhost:${port}/`,
      (port: number) => `http://[::1]:${port}/`,
      (port: number) => `http://[::ffff:127.0.0.1]:${port}/`,
      (port: number) => `http://0.0.0.0:${port}/`,
      (port: number) => `http://2130706433:${port}/`,
      () => 'http://169.254.169.254/latest/meta-data/',
      () => 'http://10.0.0.1/',
      () => 'http://192.168.1.1/'
    ]
    targets.forEach(target => {
      it(target(0), async () => {
        const url = target(port)
        let error: unknown
        try {
          await fetchExternalImage(url)
        } catch (err) {
          error = err
        }
        expect(error).to.be.instanceOf(Error)
        expect(hits).to.equal(0)
      })
    })
  })

  it('should block non-HTTP protocols', async () => {
    let error: unknown
    try {
      await fetchExternalImage('file:///etc/passwd')
    } catch (err) {
      error = err
    }
    expect((error as Error).message).to.match(/disallowed protocol/)
  })

  it('should classify private, loopback and link-local addresses as blocked', () => {
    for (const address of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.0.1', '169.254.169.254', '0.0.0.0', '::1', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1']) {
      expect(isBlockedAddress(address), address).to.equal(true)
    }
  })

  it('should classify public addresses as allowed', () => {
    for (const address of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) {
      expect(isBlockedAddress(address), address).to.equal(false)
    }
  })
})
