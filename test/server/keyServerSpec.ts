/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { denyDirectoryListing, serveKeyFiles } from '../../routes/keyServer'
const expect = chai.expect
chai.use(sinonChai)

describe('keyServer', () => {
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    req = { params: { } }
    res = { sendFile: sinon.spy(), status: sinon.spy() }
    next = sinon.spy()
  })

  it('should serve public key file from folder /encryptionkeys', () => {
    req.params.file = 'jwt.pub'

    serveKeyFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/encryptionkeys[/\\]jwt.pub/))
  })

  it('should raise error for files outside the public allowlist', () => {
    req.params.file = 'premium.key'

    serveKeyFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(res.status).to.have.been.calledWith(403)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should raise error for path traversal attempts', () => {
    req.params.file = '../../../../nice.try'

    serveKeyFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should raise error when browsing the key directory itself', () => {
    req.path = '/'

    denyDirectoryListing()(req, res, next)

    expect(res.status).to.have.been.calledWith(404)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should pass on requests for individual key files', () => {
    req.path = '/jwt.pub'

    denyDirectoryListing()(req, res, next)

    expect(next).to.have.been.calledWith()
  })
})
