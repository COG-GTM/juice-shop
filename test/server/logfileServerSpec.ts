/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { serveLogFiles } from '../../routes/logfileServer'
const expect = chai.expect
chai.use(sinonChai)

describe('logfileServer', () => {
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    res = { sendFile: sinon.spy(), status: sinon.spy() }
    req = { params: {} }
    next = sinon.spy()
  })

  it('should serve log files from folder /logs', () => {
    req.params.file = 'access.log.2026-10-30'

    serveLogFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/logs[/\\]access\.log\.2026-10-30$/))
  })

  it('should reject file names containing forward slashes', () => {
    req.params.file = '../package.json'

    serveLogFiles()(req, res, next)

    expect(res.sendFile).to.have.callCount(0)
    expect(res.status).to.have.been.calledWith(403)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should reject file names containing backslashes', () => {
    req.params.file = '..\\package.json'

    serveLogFiles()(req, res, next)

    expect(res.sendFile).to.have.callCount(0)
    expect(res.status).to.have.been.calledWith(403)
  })

  it('should reject file names resolving to the logs folder itself', () => {
    req.params.file = '..'

    serveLogFiles()(req, res, next)

    expect(res.sendFile).to.have.callCount(0)
    expect(res.status).to.have.been.calledWith(403)
  })
})
