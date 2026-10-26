/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { serveQuarantineFiles } from '../../routes/quarantineServer'
const expect = chai.expect
chai.use(sinonChai)

describe('quarantineServer', () => {
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    req = { params: { } }
    res = { sendFile: sinon.spy(), status: sinon.spy() }
    next = sinon.spy()
  })

  it('should serve requested file from folder /ftp/quarantine', () => {
    req.params.file = 'test.file'

    serveQuarantineFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith('test.file', sinon.match.has('root', sinon.match(/ftp[/\\]quarantine$/)))
  })

  it('should raise error for slashes in filename', () => {
    req.params.file = '../../../../nice.try'

    serveQuarantineFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should raise error for backslashes in filename', () => {
    req.params.file = '..\\..\\package.json'

    serveQuarantineFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(res.status).to.have.been.calledWith(403)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })
})
