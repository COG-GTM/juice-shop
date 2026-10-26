/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import chai from 'chai'
import sinon from 'sinon'
import sinonChai from 'sinon-chai'
import * as security from '../../lib/insecurity'
import { UserModel } from '../../models/user'
import { profileImageUrlUpload } from '../../routes/profileImageUrlUpload'

const expect = chai.expect
chai.use(sinonChai)

const pngBytes = Buffer.from('89504e470d0a1a0a0000000d4948445200000001000000010806000000', 'hex')
const svgBytes = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>')

describe('profileImageUrlUpload', () => {
  let req: any
  let res: any
  let next: any
  let writeFileStub: sinon.SinonStub
  let userUpdate: sinon.SinonStub

  beforeEach(() => {
    req = { body: {}, cookies: { token: 'token' }, app: { locals: {} }, socket: {} }
    res = { location: sinon.spy(), redirect: sinon.spy() }
    next = sinon.spy()
    writeFileStub = sinon.stub(fs, 'writeFile').resolves()
    userUpdate = sinon.stub().resolves()
    sinon.stub(security.authenticatedUsers, 'get').returns({ data: { id: 42 } } as any)
    sinon.stub(UserModel, 'findByPk').resolves({ update: userUpdate } as any)
  })

  afterEach(() => {
    sinon.restore()
  })

  function stubFetch (body: Buffer) {
    sinon.stub(global, 'fetch').resolves(new Response(body, { status: 200 }))
  }

  it('stores a raster image using the extension of its detected type', async () => {
    stubFetch(pngBytes)
    req.body.imageUrl = 'https://example.com/pic.svg'

    await profileImageUrlUpload()(req, res, next)

    expect(writeFileStub).to.have.been.calledOnceWith('frontend/dist/frontend/assets/public/images/uploads/42.png')
    expect(userUpdate).to.have.been.calledWith({ profileImage: '/assets/public/images/uploads/42.png' })
  })

  it('does not store SVG content on the server', async () => {
    stubFetch(svgBytes)
    req.body.imageUrl = 'https://example.com/pic.svg'

    await profileImageUrlUpload()(req, res, next)

    expect(writeFileStub).to.have.callCount(0)
    expect(userUpdate).to.have.been.calledWith({ profileImage: 'https://example.com/pic.svg' })
  })

  it('does not store SVG content disguised with a raster extension', async () => {
    stubFetch(svgBytes)
    req.body.imageUrl = 'https://example.com/pic.png'

    await profileImageUrlUpload()(req, res, next)

    expect(writeFileStub).to.have.callCount(0)
  })
})
