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
    res = { sendFile: sinon.spy(), status: sinon.spy() }
    req = { params: {}, query: {} }
    next = sinon.spy()
  })

  it('should serve files from folder /ftp/quarantine', () => {
    req.params.file = 'juicy_malware_linux_amd_64.url'

    serveQuarantineFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]quarantine[/\\]juicy_malware_linux_amd_64\.url$/))
    expect(next).to.have.not.been.calledWith(sinon.match.any)
  })

  for (const file of ['../../../../nice.try', '..\\..\\config\\default.yml', 'C:\\Windows\\win.ini', 'C:win.ini', '..', '.', 'evil\0.url']) {
    it(`should raise error for file name ${JSON.stringify(file)}`, () => {
      req.params.file = file

      serveQuarantineFiles()(req, res, next)

      expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
      expect(res.status).to.have.been.calledWith(403)
      expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
    })
  }
})
