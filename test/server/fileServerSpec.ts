/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { servePublicFiles } from '../../routes/fileServer'
const expect = chai.expect
chai.use(sinonChai)

describe('fileServer', () => {
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    res = { sendFile: sinon.spy(), status: sinon.spy() }
    req = { params: {}, query: {} }
    next = sinon.spy()
  })

  it('should serve legal.md from folder /ftp', () => {
    req.params.file = 'legal.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]legal\.md/))
  })

  it('should serve order confirmation PDFs from folder /ftp', () => {
    req.params.file = 'order_5267-f9cd5882f54c75a3.pdf'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]order_5267-f9cd5882f54c75a3\.pdf/))
  })

  it('should raise error for slashes in filename', () => {
    req.params.file = '../../../../nice.try'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(res.status).to.have.been.calledWith(403)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  for (const file of ['acquisitions.md', 'announcement_encrypted.md', 'incident-support.kdbx', 'test.md', 'test.pdf', 'order_.pdf', 'order_5267-f9cd5882f54c75a3.pdf.bak']) {
    it(`should not serve non-allowlisted file ${file}`, () => {
      req.params.file = file

      servePublicFiles()(req, res, next)

      expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
      expect(res.status).to.have.been.calledWith(404)
      expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
    })
  }

  for (const file of ['eastere.gg%00.md', 'package.json.bak%00.md', 'coupons_2013.md.bak%00.md', 'suspicious_errors.yml%00.md', 'encrypt.pyc%00.pdf', 'acquisitions.md%00.pdf']) {
    it(`should not serve ${file} via Poison Null Byte attack`, () => {
      req.params.file = file

      servePublicFiles()(req, res, next)

      expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
      expect(res.status).to.have.been.calledWith(404)
      expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
    })
  }
})
