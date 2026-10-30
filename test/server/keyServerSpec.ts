/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { serveKeyFiles } from '../../routes/keyServer'
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

  for (const file of ['premium.key', 'jwt.pub', 'doesnotexist.md']) {
    it(`should not serve ${file} from folder /encryptionkeys`, () => {
      req.params.file = file

      serveKeyFiles()(req, res, next)

      expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
      expect(res.status).to.have.been.calledWith(404)
      expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
    })
  }

  it('should not serve anything for the bare /encryptionkeys folder', () => {
    serveKeyFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(res.status).to.have.been.calledWith(404)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should not serve file names containing slashes', () => {
    req.params.file = '../../../../nice.try'

    serveKeyFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should not serve file names containing backslashes', () => {
    req.params.file = '..\\..\\data\\juiceshop.sqlite'

    serveKeyFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(res.status).to.have.been.calledWith(404)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })
})
