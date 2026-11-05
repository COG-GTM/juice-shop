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

  it('should serve allowlisted public files from folder /ftp', () => {
    req.params.file = 'legal.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]legal\.md/))
  })

  for (const file of ['order_1234-0123456789abcdef.pdf', 'acquisitions.md', 'incident-support.kdbx', 'coupons_2013.md.bak', 'package.json.bak', 'encrypt.pyc', 'eastere.gg']) {
    it(`should deny access to non-public file ${file}`, () => {
      req.params.file = file

      servePublicFiles()(req, res, next)

      expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
      expect(res.status).to.have.been.calledWith(403)
      expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
    })
  }

  for (const file of ['coupons_2013.md.bak\u00001.md', 'package.json.bak\u0000.pdf', 'eastere.gg%00.md', 'legal.md\u0000.pdf']) {
    it(`should deny Poison Null Byte variant ${JSON.stringify(file)}`, () => {
      req.params.file = file

      servePublicFiles()(req, res, next)

      expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
      expect(res.status).to.have.been.calledWith(403)
    })
  }

  it('should raise error for slashes in filename', () => {
    req.params.file = '../../etc/passwd'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })
})
