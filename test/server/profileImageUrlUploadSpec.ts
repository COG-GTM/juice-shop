/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { MAX_IMAGE_URL_LENGTH, profileImageUrlUpload } from '../../routes/profileImageUrlUpload'
import { authenticatedUsers } from '../../lib/insecurity'
import { UserModel } from '../../models/user'
const expect = chai.expect
chai.use(sinonChai)

describe('profileImageUrlUpload', () => {
  const token = 'profileImageUrlUploadSpecToken'
  let req: any
  let res: any
  let next: any
  let fetchStub: sinon.SinonStub

  beforeEach(() => {
    req = { body: {}, cookies: {}, app: { locals: { abused_ssrf_bug: false } }, socket: { remoteAddress: '127.0.0.1' } }
    res = { location: sinon.spy(), redirect: sinon.spy(), send: sinon.spy() }
    res.status = sinon.stub().returns(res)
    next = sinon.spy()
    fetchStub = sinon.stub(globalThis, 'fetch').resolves({ ok: false } as unknown as Response)
    sinon.stub(UserModel, 'findByPk').resolves(null)
    authenticatedUsers.put(token, { data: { id: 42 } } as any)
  })

  afterEach(() => {
    sinon.restore()
  })

  it('should block anonymous users without evaluating a long imageUrl', async () => {
    req.body.imageUrl = 'a'.repeat(1000000) + 'solve/challenges/server-side'

    const start = Date.now()
    await profileImageUrlUpload()(req, res, next)

    expect(Date.now() - start).to.be.below(1000)
    expect(next).to.have.been.calledOnce
    expect(next.firstCall.args[0].message).to.contain('Blocked illegal activity')
    expect(req.app.locals.abused_ssrf_bug).to.equal(false)
    expect(fetchStub).to.not.have.been.called
  })

  it('should reject an imageUrl longer than the maximum length', async () => {
    req.cookies.token = token
    req.body.imageUrl = 'a'.repeat(MAX_IMAGE_URL_LENGTH + 1)

    await profileImageUrlUpload()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
    expect(fetchStub).to.not.have.been.called
    expect(next).to.not.have.been.called
  })

  it('should reject a non-string imageUrl', async () => {
    req.cookies.token = token
    req.body.imageUrl = ['http://localhost/a.png', 'http://localhost/b.png']

    await profileImageUrlUpload()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
    expect(fetchStub).to.not.have.been.called
  })

  it('should flag the SSRF challenge for a logged-in user requesting the server-side solve URL', async () => {
    req.cookies.token = token
    req.body.imageUrl = 'http://localhost:3000/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3'

    await profileImageUrlUpload()(req, res, next)

    expect(req.app.locals.abused_ssrf_bug).to.equal(true)
    expect(fetchStub).to.have.been.calledWith(req.body.imageUrl)
    expect(res.redirect).to.have.been.called
  })

  it('should not flag the SSRF challenge for an ordinary image URL', async () => {
    req.cookies.token = token
    req.body.imageUrl = 'https://example.com/image.png'

    await profileImageUrlUpload()(req, res, next)

    expect(req.app.locals.abused_ssrf_bug).to.equal(false)
    expect(res.redirect).to.have.been.called
  })
})
