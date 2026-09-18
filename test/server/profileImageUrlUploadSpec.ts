/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { profileImageUrlUpload } from '../../routes/profileImageUrlUpload'
import { UserModel } from '../../models/user'
const expect = chai.expect
chai.use(sinonChai)

describe('profileImageUrlUpload', () => {
  let req: any
  let res: any
  let next: any
  let findByPk: sinon.SinonStub

  beforeEach(() => {
    req = { body: {}, cookies: {}, app: { locals: {} }, socket: { remoteAddress: '127.0.0.1' } }
    res = { location: sinon.spy(), redirect: sinon.spy() }
    next = sinon.spy()
    findByPk = sinon.stub(UserModel, 'findByPk')
  })

  afterEach(() => {
    findByPk.restore()
  })

  it('should block anonymous users from setting a profile image URL', async () => {
    req.body.imageUrl = 'https://placekitten.com/100/100'

    await profileImageUrlUpload()(req, res, next)

    expect(next).to.have.been.calledWithMatch({ message: 'Blocked illegal activity by 127.0.0.1' })
    expect(findByPk).to.not.have.been.called
    expect(res.redirect).to.not.have.been.called
  })

  it('should block users with an unknown token from setting a profile image URL', async () => {
    req.body.imageUrl = 'https://placekitten.com/100/100'
    req.cookies.token = 'unknown-token'

    await profileImageUrlUpload()(req, res, next)

    expect(next).to.have.been.calledWithMatch({ message: 'Blocked illegal activity by 127.0.0.1' })
    expect(findByPk).to.not.have.been.called
    expect(res.redirect).to.not.have.been.called
  })

  it('should flag the SSRF challenge even for anonymous users', async () => {
    req.body.imageUrl = 'http://localhost:3000/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3'

    await profileImageUrlUpload()(req, res, next)

    expect(req.app.locals.abused_ssrf_bug).to.equal(true)
    expect(next).to.have.been.calledWithMatch({ message: 'Blocked illegal activity by 127.0.0.1' })
  })

  it('should redirect to the profile page without an image URL in the request', async () => {
    await profileImageUrlUpload()(req, res, next)

    expect(next).to.not.have.been.called
    expect(res.redirect).to.have.been.calledWith(process.env.BASE_PATH + '/profile')
  })
})
