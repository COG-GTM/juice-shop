/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { profileImageUrlUpload, MAX_IMAGE_URL_LENGTH } from '../../routes/profileImageUrlUpload'
import { authenticatedUsers } from '../../lib/insecurity'
import { UserModel } from '../../models/user'
const expect = chai.expect
chai.use(sinonChai)

describe('profileImageUrlUpload', () => {
  const token = 'profileImageUrlUploadSpecToken'
  const hugeNonMatchingUrl = 'a'.repeat(1_000_000)
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    req = { body: {}, cookies: {}, socket: { remoteAddress: '127.0.0.1' }, app: { locals: {} } }
    res = { location: sinon.spy(), redirect: sinon.spy(), status: sinon.stub(), send: sinon.spy() }
    res.status.returns(res)
    next = sinon.spy()
  })

  afterEach(() => {
    Reflect.deleteProperty(authenticatedUsers.tokenMap, token)
    sinon.restore()
  })

  it('should reject an anonymous 1 MB imageUrl without evaluating it', async () => {
    req.body.imageUrl = hugeNonMatchingUrl + 'solve/challenges/server-side'

    const start = process.hrtime.bigint()
    await profileImageUrlUpload()(req, res, next)
    const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6

    expect(next).to.have.been.calledWithMatch(sinon.match.instanceOf(Error).and(sinon.match.has('message', 'Blocked illegal activity by 127.0.0.1')))
    expect(req.app.locals.abused_ssrf_bug).to.equal(undefined)
    expect(elapsedMs).to.be.below(100)
  })

  it('should reject an overlong imageUrl of a logged-in user with 400 in constant time', async () => {
    authenticatedUsers.put(token, { data: { id: 1 } as unknown as UserModel })
    req.cookies.token = token
    req.body.imageUrl = hugeNonMatchingUrl
    const fetchStub = sinon.stub(globalThis, 'fetch')

    const start = process.hrtime.bigint()
    await profileImageUrlUpload()(req, res, next)
    const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6

    expect(res.status).to.have.been.calledWith(400)
    expect(fetchStub.called).to.equal(false)
    expect(next.called).to.equal(false)
    expect(elapsedMs).to.be.below(100)
  })

  it('should reject a non-string imageUrl of a logged-in user with 400', async () => {
    authenticatedUsers.put(token, { data: { id: 1 } as unknown as UserModel })
    req.cookies.token = token
    req.body.imageUrl = ['http://localhost:3000/solve/challenges/server-side']
    const fetchStub = sinon.stub(globalThis, 'fetch')

    await profileImageUrlUpload()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
    expect(fetchStub.called).to.equal(false)
    expect(req.app.locals.abused_ssrf_bug).to.equal(undefined)
  })

  it('should still flag the SSRF challenge URL of a logged-in user', async () => {
    authenticatedUsers.put(token, { data: { id: 1 } as unknown as UserModel })
    req.cookies.token = token
    req.body.imageUrl = 'http://localhost:3000/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3'
    expect(req.body.imageUrl.length).to.be.at.most(MAX_IMAGE_URL_LENGTH)
    sinon.stub(globalThis, 'fetch').rejects(new Error('offline'))
    sinon.stub(UserModel, 'findByPk').resolves(null)

    await profileImageUrlUpload()(req, res, next)

    expect(req.app.locals.abused_ssrf_bug).to.equal(true)
  })
})
