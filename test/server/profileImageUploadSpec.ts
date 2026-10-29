/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import fsPromises from 'node:fs/promises'
import path from 'node:path'
import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { UserModel } from '../../models/user'
import { authenticatedUsers } from '../../lib/insecurity'
import { profileImageFileUpload, profileImageUploadPath } from '../../routes/profileImageFileUpload'
import { profileImageUrlUpload } from '../../routes/profileImageUrlUpload'
const expect = chai.expect
chai.use(sinonChai)

const uploadsDir = path.resolve('frontend/dist/frontend/assets/public/images/uploads')
const image = fs.readFileSync(path.resolve(__dirname, '../files/validProfileImage.jpg'))

describe('profileImageUpload', () => {
  let req: any
  let res: any
  let next: any
  let writeFile: sinon.SinonStub
  let findByPk: sinon.SinonStub
  let update: sinon.SinonStub

  function loginAs (id: unknown) {
    const token = `token-${String(id)}`
    authenticatedUsers.put(token, { data: { id } } as any)
    req.cookies.token = token
  }

  beforeEach(() => {
    req = { cookies: {}, body: {}, file: { buffer: image }, socket: { remoteAddress: '127.0.0.1' }, app: { locals: {} } }
    res = { status: sinon.stub(), location: sinon.spy(), redirect: sinon.spy() }
    next = sinon.spy()
    writeFile = sinon.stub(fsPromises, 'writeFile').resolves()
    update = sinon.stub().resolves()
    findByPk = sinon.stub(UserModel, 'findByPk').resolves({ update } as any)
  })

  afterEach(() => {
    sinon.restore()
  })

  describe('profileImageUploadPath', () => {
    it('should build a path inside the uploads folder for a positive integer id', () => {
      expect(profileImageUploadPath(1, 'jpg')).to.equal(path.join(uploadsDir, '1.jpg'))
      expect(profileImageUploadPath('23', 'png')).to.equal(path.join(uploadsDir, '23.png'))
    })

    it('should reject ids that are not positive integers', () => {
      for (const id of ['../x', '../../../../ftp/evil', '1/../2', '1.5', '-1', '', ' 1', 0, -1, 1.5, NaN, null, undefined, {}]) {
        expect(profileImageUploadPath(id, 'jpg'), String(id)).to.equal(null)
      }
    })

    it('should reject extensions containing path characters', () => {
      expect(profileImageUploadPath(1, '/../../x')).to.equal(null)
    })
  })

  describe('file upload', () => {
    it('should reject a session whose user id is a path with 400 and write no file', async () => {
      loginAs('../x')

      await profileImageFileUpload()(req, res, next)

      expect(res.status).to.have.been.calledWith(400)
      expect(next).to.have.been.calledWithMatch(sinon.match.instanceOf(Error))
      expect(writeFile).to.have.callCount(0)
      expect(findByPk).to.have.callCount(0)
      expect(res.redirect).to.have.callCount(0)
    })

    it('should reject a numeric user id without a matching user with 400 and write no file', async () => {
      loginAs(424242)
      findByPk.resolves(null)

      await profileImageFileUpload()(req, res, next)

      expect(res.status).to.have.been.calledWith(400)
      expect(writeFile).to.have.callCount(0)
      expect(res.redirect).to.have.callCount(0)
    })

    it('should write the image to <id>.<ext> in the uploads folder for a valid user', async () => {
      loginAs(1)

      await profileImageFileUpload()(req, res, next)

      expect(findByPk).to.have.been.calledWith(1)
      expect(writeFile).to.have.been.calledWith(path.join(uploadsDir, '1.jpg'), image)
      expect(update).to.have.been.calledWith({ profileImage: 'assets/public/images/uploads/1.jpg' })
      expect(next).to.have.callCount(0)
      expect(res.redirect).to.have.callCount(1)
    })
  })

  describe('url upload', () => {
    it('should reject a session whose user id is a path with 400 before fetching or writing', async () => {
      const fetch = sinon.stub(globalThis, 'fetch')
      const createWriteStream = sinon.stub(fs, 'createWriteStream')
      loginAs('../../../../ftp/evil')
      req.body.imageUrl = 'https://example.com/evil.svg'

      await profileImageUrlUpload()(req, res, next)

      expect(res.status).to.have.been.calledWith(400)
      expect(next).to.have.been.calledWithMatch(sinon.match.instanceOf(Error))
      expect(fetch).to.have.callCount(0)
      expect(createWriteStream).to.have.callCount(0)
      expect(findByPk).to.have.callCount(0)
    })
  })
})
