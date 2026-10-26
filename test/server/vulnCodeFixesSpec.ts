/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { serveCodeFixes, checkCorrectFix, readFixes } from '../../routes/vulnCodeFixes'

const expect = chai.expect
chai.use(sinonChai)

describe('vulnCodeFixes routes', () => {
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    res = { json: sinon.spy(), status: sinon.stub(), __: sinon.stub().returnsArg(0) }
    res.status.returns(res)
    next = sinon.spy()
  })

  it('should identify the correct fix from its file name', () => {
    const { fixes, correct } = readFixes('loginAdminChallenge')

    expect(fixes).to.have.lengthOf(4)
    expect(correct).to.equal(3)
  })

  it('should return no fixes for unknown challenge', () => {
    const { fixes, correct } = readFixes('doesNotExistChallenge')

    expect(fixes).to.have.lengthOf(0)
    expect(correct).to.equal(-1)
  })

  describe('serveCodeFixes', () => {
    it('should serve all fix options of a coding challenge', () => {
      req = { params: { key: 'loginAdminChallenge' } }

      serveCodeFixes()(req, res, next)

      expect(res.status).to.have.been.calledWith(200)
      expect(res.json.firstCall.args[0].fixes).to.have.lengthOf(4)
    })

    it('should respond with 404 for unknown challenge', () => {
      req = { params: { key: 'doesNotExistChallenge' } }

      serveCodeFixes()(req, res, next)

      expect(res.status).to.have.been.calledWith(404)
      expect(res.json).to.have.been.calledWith({ error: 'No fixes found for the snippet!' })
    })
  })

  describe('checkCorrectFix', () => {
    it('should return negative verdict with explanation for wrong fix', async () => {
      req = { body: { key: 'loginAdminChallenge', selectedFix: 0 } }

      await checkCorrectFix()(req, res, next)

      expect(res.status).to.have.been.calledWith(200)
      expect(res.json).to.have.been.calledWith({ verdict: false, explanation: sinon.match('custom-built blocklist mechanism') })
    })

    it('should respond with 404 for unknown challenge', async () => {
      req = { body: { key: 'doesNotExistChallenge', selectedFix: 0 } }

      await checkCorrectFix()(req, res, next)

      expect(res.status).to.have.been.calledWith(404)
      expect(res.json).to.have.been.calledWith({ error: 'No fixes found for the snippet!' })
    })
  })
})
