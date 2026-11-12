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

  it('should serve the public legal.md from folder /ftp', () => {
    req.params.file = 'legal.md'

    servePublicFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/ftp[/\\]legal\.md/))
  })

  for (const file of ['acquisitions.md', 'order_1234-5678.pdf', 'incident-support.kdbx', 'eastere.gg%00.md', 'package.json.bak%00.md', 'coupons_2013.md.bak%00.md', 'suspicious_errors.yml%00.md', '../package.json', 'nice.try']) {
    it(`should refuse to serve non-public file ${file}`, () => {
      req.params.file = file

      servePublicFiles()(req, res, next)

      expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
      expect(res.status).to.have.been.calledWith(403)
      expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
    })
  }
})
