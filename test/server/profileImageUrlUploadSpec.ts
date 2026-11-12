/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import chai from 'chai'
import sinon from 'sinon'
import * as security from '../../lib/insecurity'
import { UserModel } from '../../models/user'
import { profileImageUrlUpload } from '../../routes/profileImageUrlUpload'

const expect = chai.expect

describe('profileImageUrlUpload', () => {
  it('should not flag the SSRF challenge for unauthenticated requests', async () => {
    const req: any = {
      body: { imageUrl: 'http://localhost:3000/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3' },
      cookies: { token: 'unknown' },
      socket: { remoteAddress: '127.0.0.1' },
      app: { locals: { abused_ssrf_bug: false } }
    }
    let error: unknown
    await profileImageUrlUpload()(req, {} as any, (err?: unknown) => { error = err })

    expect(error).to.be.an('error')
    expect(req.app.locals.abused_ssrf_bug).to.equal(false)
  })
  it('should not flag the SSRF challenge when an authenticated user submits a rejected internal URL', async () => {
    security.authenticatedUsers.put('ssrf-spec-token', { data: { id: 4711 } } as any)
    const req: any = {
      body: { imageUrl: 'http://127.0.0.1:3000/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3' },
      cookies: { token: 'ssrf-spec-token' },
      socket: { remoteAddress: '127.0.0.1' },
      app: { locals: { abused_ssrf_bug: false } }
    }
    let redirected = false
    const res: any = { location: () => {}, redirect: () => { redirected = true } }
    let error: unknown
    await profileImageUrlUpload()(req, res, (err?: unknown) => { error = err })

    expect(error).to.equal(undefined)
    expect(redirected).to.equal(true)
    expect(req.app.locals.abused_ssrf_bug).to.equal(false)
  })
  it('should persist a verified image and link it as the profile image', async () => {
    security.authenticatedUsers.put('ssrf-spec-token-ok', { data: { id: 4712 } } as any)
    const image = { data: Buffer.from([0x89, 0x50, 0x4e, 0x47]), extension: 'png' }
    const fetchStub = sinon.stub().resolves(image)
    const writeStub = sinon.stub(fs.promises, 'writeFile').resolves()
    const update = sinon.stub().resolves()
    const findStub = sinon.stub(UserModel, 'findByPk').resolves({ update } as any)
    try {
      const req: any = { body: { imageUrl: 'https://images.example/cat.png' }, cookies: { token: 'ssrf-spec-token-ok' }, app: { locals: {} } }
      let redirected = false
      const res: any = { location: () => {}, redirect: () => { redirected = true } }
      let error: unknown
      await profileImageUrlUpload(fetchStub)(req, res, (err?: unknown) => { error = err })

      expect(error).to.equal(undefined)
      expect(redirected).to.equal(true)
      expect(fetchStub.calledOnceWith('https://images.example/cat.png')).to.equal(true)
      expect(writeStub.calledOnceWith('frontend/dist/frontend/assets/public/images/uploads/4712.png', image.data)).to.equal(true)
      expect(findStub.calledOnceWith(4712)).to.equal(true)
      expect(update.calledOnceWith({ profileImage: '/assets/public/images/uploads/4712.png' })).to.equal(true)
    } finally {
      writeStub.restore()
      findStub.restore()
    }
  })
})
