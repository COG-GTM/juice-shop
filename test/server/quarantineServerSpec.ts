/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import * as security from '../../lib/insecurity'
import { serveQuarantineFiles } from '../../routes/quarantineServer'
const expect = chai.expect
chai.use(sinonChai)

describe('quarantineServer', () => {
  let req: any
  let res: any
  let next: any

  before(() => {
    security.authenticatedUsers.put('quarantineSpecAdmin', { data: { id: 1, email: 'admin@juice-sh.op', role: 'admin' } } as any)
    security.authenticatedUsers.put('quarantineSpecJim', { data: { id: 2, email: 'jim@juice-sh.op', role: 'customer' } } as any)
  })

  beforeEach(() => {
    req = { params: { file: 'juicy_malware_linux_amd_64.url' }, cookies: {}, headers: {} }
    res = { sendFile: sinon.spy(), status: sinon.spy() }
    next = sinon.spy()
  })

  it('should serve quarantined files to admins', () => {
    req.headers.authorization = 'Bearer quarantineSpecAdmin'

    serveQuarantineFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]quarantine[/\\]juicy_malware_linux_amd_64\.url/))
  })

  it('should reject anonymous requests with 401', () => {
    serveQuarantineFiles()(req, res, next)

    expect(res.status).to.have.been.calledWith(401)
    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should reject non-admin users with 403', () => {
    req.headers.authorization = 'Bearer quarantineSpecJim'

    serveQuarantineFiles()(req, res, next)

    expect(res.status).to.have.been.calledWith(403)
    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
  })

  it('should raise error for slashes in filename', () => {
    req.headers.authorization = 'Bearer quarantineSpecAdmin'
    req.params.file = '../../../../nice.try'

    serveQuarantineFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })
})
