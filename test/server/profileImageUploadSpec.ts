/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { inspect } from 'node:util'
import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'

import * as security from '../../lib/insecurity'
import { profileImageUploadDir, profileImageUploadPath, toProfileImageUserId } from '../../lib/profileImageUpload'
import { profileImageFileUpload } from '../../routes/profileImageFileUpload'
import { profileImageUrlUpload } from '../../routes/profileImageUrlUpload'

const expect = chai.expect
chai.use(sinonChai)

describe('profileImageUpload', () => {
  describe('toProfileImageUserId', () => {
    it('accepts positive integers', () => {
      expect(toProfileImageUserId(1)).to.equal(1)
      expect(toProfileImageUserId(23)).to.equal(23)
      expect(toProfileImageUserId('42')).to.equal(42)
    })

    for (const id of [undefined, null, 0, -1, 1.5, Number.NaN, Infinity, '', '1a', '../x', '../../../../tmp/evil', '1/../../x', ' 1', '0x10', {}, [1]]) {
      it(`rejects ${inspect(id)}`, () => {
        expect(toProfileImageUserId(id)).to.equal(undefined)
      })
    }
  })

  describe('profileImageUploadPath', () => {
    it('resolves inside the uploads directory', () => {
      expect(profileImageUploadPath(7, 'png')).to.equal(path.join(profileImageUploadDir, '7.png'))
    })

    it('rejects non-integer ids and unsafe extensions', () => {
      expect(profileImageUploadPath('../x' as unknown as number, 'png')).to.equal(undefined)
      expect(profileImageUploadPath(-1, 'png')).to.equal(undefined)
      expect(profileImageUploadPath(7, 'png/../../x')).to.equal(undefined)
      expect(profileImageUploadPath(7, '')).to.equal(undefined)
    })
  })

  describe('route handlers with a non-numeric session user id', () => {
    const token = 'crafted-profile-image-token'
    const escapedName = 'profile-image-upload-spec-escape'
    let req: any
    let res: any
    let next: any

    beforeEach(() => {
      security.authenticatedUsers.put(token, { data: { id: `../${escapedName}` } } as any)
      res = { status: sinon.stub(), location: sinon.stub(), redirect: sinon.stub() }
      next = sinon.spy()
    })

    afterEach(() => {
      delete security.authenticatedUsers.tokenMap[token]
      sinon.restore()
    })

    it('profileImageFileUpload rejects the request without writing a file', async () => {
      const writeFile = sinon.stub(fs.promises, 'writeFile').resolves()
      req = {
        cookies: { token },
        file: { buffer: fs.readFileSync(path.resolve(__dirname, '../files/validProfileImage.jpg')) },
        socket: {}
      }

      await profileImageFileUpload()(req, res, next)

      expect(res.status).to.have.been.calledWith(400)
      expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error).and(sinon.match.has('message', 'Invalid user id in session')))
      expect(writeFile).to.have.callCount(0)
      expect(res.redirect).to.have.callCount(0)
    })

    it('profileImageUrlUpload rejects the request before fetching the image', async () => {
      const fetch = sinon.stub(globalThis, 'fetch')
      const createWriteStream = sinon.spy(fs, 'createWriteStream')
      req = {
        body: { imageUrl: 'https://example.com/evil.svg' },
        cookies: { token },
        app: { locals: {} },
        socket: {}
      }

      await profileImageUrlUpload()(req, res, next)

      expect(res.status).to.have.been.calledWith(400)
      expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error).and(sinon.match.has('message', 'Invalid user id in session')))
      expect(fetch).to.have.callCount(0)
      expect(createWriteStream).to.have.callCount(0)
      expect(res.redirect).to.have.callCount(0)
    })
  })
})
