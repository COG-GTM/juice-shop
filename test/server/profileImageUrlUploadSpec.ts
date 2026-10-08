/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'

import * as security from '../../lib/insecurity'
import { UserModel } from '../../models/user'
import { profileImageUrlUpload, MAX_PROFILE_IMAGE_BYTES } from '../../routes/profileImageUrlUpload'

const expect = chai.expect
chai.use(sinonChai)

const PNG = Buffer.from('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d4944415478da63f8ffff3f0005fe02fea7d6a4b50000000049454e44ae426082', 'hex')
const SVG = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"><script>alert(1)</script></svg>')

describe('profileImageUrlUpload', () => {
  let req: any
  let res: any
  let next: sinon.SinonSpy
  let update: sinon.SinonStub
  let writeFile: sinon.SinonStub

  function respondWith (body: Buffer) {
    sinon.stub(globalThis, 'fetch').resolves(new Response(body, { status: 200 }))
  }

  beforeEach(() => {
    req = { body: { imageUrl: 'https://attacker.example/x.svg' }, cookies: { token: 'token' }, app: { locals: {} }, socket: {} }
    res = { location: sinon.spy(), redirect: sinon.spy() }
    next = sinon.spy()
    update = sinon.stub().resolves()
    sinon.stub(security.authenticatedUsers, 'get').returns({ data: { id: 42 } } as any)
    sinon.stub(UserModel, 'findByPk').resolves({ update } as any)
    writeFile = sinon.stub(fs, 'writeFile').resolves()
    sinon.stub(fs, 'rm').resolves()
  })

  afterEach(() => {
    sinon.restore()
  })

  it('never stores an SVG fetched from a .svg URL on the application origin', async () => {
    respondWith(SVG)

    await profileImageUrlUpload()(req, res, next)

    expect(writeFile.called).to.equal(false)
    expect(update).to.have.been.calledOnceWith({ profileImage: 'https://attacker.example/x.svg' })
    expect(res.redirect.called).to.equal(true)
  })

  it('stores a real PNG under the extension detected from its content, not from the URL', async () => {
    req.body.imageUrl = 'https://images.example/avatar.svg'
    respondWith(PNG)

    await profileImageUrlUpload()(req, res, next)

    expect(writeFile).to.have.been.calledOnceWith('frontend/dist/frontend/assets/public/images/uploads/42.png', PNG)
    expect(fs.rm).to.have.been.calledWith('frontend/dist/frontend/assets/public/images/uploads/42.svg', { force: true })
    expect(update).to.have.been.calledOnceWith({ profileImage: '/assets/public/images/uploads/42.png' })
  })

  it('does not store HTML disguised behind an image extension', async () => {
    req.body.imageUrl = 'https://attacker.example/x.png'
    respondWith(Buffer.from('<html><script>alert(1)</script></html>'))

    await profileImageUrlUpload()(req, res, next)

    expect(writeFile.called).to.equal(false)
    expect(update).to.have.been.calledOnceWith({ profileImage: 'https://attacker.example/x.png' })
  })

  it('does not store responses larger than the size limit', async () => {
    req.body.imageUrl = 'https://images.example/huge.png'
    respondWith(Buffer.concat([PNG, Buffer.alloc(MAX_PROFILE_IMAGE_BYTES)]))

    await profileImageUrlUpload()(req, res, next)

    expect(writeFile.called).to.equal(false)
    expect(update).to.have.been.calledOnceWith({ profileImage: 'https://images.example/huge.png' })
  })
})
