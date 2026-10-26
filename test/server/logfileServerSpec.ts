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
    req = { params: { } }
    res = { sendFile: sinon.spy(), status: sinon.spy() }
    next = sinon.spy()
  })

  it('should serve requested file from folder /logs', () => {
    req.params.file = 'access.log.2026-10-26'

    serveLogFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith('access.log.2026-10-26', sinon.match({ root: sinon.match(/logs$/) }))
    expect(next).to.have.not.been.calledWith(sinon.match.any)
  })

  for (const file of ['../../../../nice.try', '..\\..\\package.json', '..\\..\\data\\juiceshop.sqlite', '..\\..\\..\\Windows\\win.ini', 'C:\\Windows\\win.ini', 'C:win.ini', '..', '.', 'access.log\0.txt']) {
    it(`should raise error for file name ${JSON.stringify(file)}`, () => {
      req.params.file = file

      serveLogFiles()(req, res, next)

      expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
      expect(res.status).to.have.been.calledWith(403)
      expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
    })
  }
})
