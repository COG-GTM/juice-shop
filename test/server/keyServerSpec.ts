/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { serveKeyFiles } from '../../routes/keyServer'
import * as security from '../../lib/insecurity'
const expect = chai.expect
chai.use(sinonChai)

describe('keyServer', () => {
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    req = { params: { } }
    res = { sendFile: sinon.spy(), status: sinon.spy(), send: sinon.spy() }
    res.type = sinon.stub().returns(res)
    next = sinon.spy()
  })

  it('should serve requested file from folder /encryptionkeys', () => {
    req.params.file = 'test.file'

    serveKeyFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/encryptionkeys[/\\]test.file/))
  })

  it('should raise error for slashes in filename', () => {
    req.params.file = '../../../../nice.try'

    serveKeyFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should serve the public key matching the active JWT signing key', () => {
    req.params.file = 'jwt.pub'

    serveKeyFiles()(req, res, next)

    expect(res.send).to.have.been.calledWith(security.publicKey)
    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
  })

  it('should not allow the JWT private key file inside a publicly served directory', () => {
    expect(security.isInPubliclyServedDirectory('encryptionkeys/jwt.key')).to.equal(true)
    expect(security.isInPubliclyServedDirectory('ftp/jwt.key')).to.equal(true)
    expect(security.isInPubliclyServedDirectory(security.privateKeyFile)).to.equal(false)
  })

  it('should not allow the JWT private key file to be symlinked into a publicly served directory', () => {
    const link = path.resolve('data', `keyServerSpec-${process.pid}`)
    fs.symlinkSync(path.resolve('encryptionkeys'), link, 'junction')
    try {
      expect(security.isInPubliclyServedDirectory(path.join(link, 'jwt.key'))).to.equal(true)
    } finally {
      fs.unlinkSync(link)
    }
  })
})
