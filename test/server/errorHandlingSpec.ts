/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import logger from '../../lib/logger'
import { exposeErrorDetails, genericErrorHandler, parseJsonBody } from '../../lib/errorHandling'

const expect = chai.expect
chai.use(sinonChai)

describe('errorHandling', () => {
  describe('exposeErrorDetails', () => {
    it('is enabled only for development and test environments', () => {
      expect(exposeErrorDetails({ NODE_ENV: 'development' })).to.equal(true)
      expect(exposeErrorDetails({ NODE_ENV: 'test' })).to.equal(true)
      expect(exposeErrorDetails({})).to.equal(false)
      expect(exposeErrorDetails({ NODE_ENV: 'production' })).to.equal(false)
      expect(exposeErrorDetails({ NODE_ENV: 'ctf' })).to.equal(false)
    })

    it('can be enabled explicitly with EXPOSE_ERROR_DETAILS=true', () => {
      expect(exposeErrorDetails({ EXPOSE_ERROR_DETAILS: 'true' })).to.equal(true)
      expect(exposeErrorDetails({ EXPOSE_ERROR_DETAILS: '1' })).to.equal(false)
    })
  })

  describe('parseJsonBody', () => {
    it('parses valid JSON', () => {
      expect(parseJsonBody('{"a":1}')).to.deep.equal({ a: 1 })
    })

    it('throws a 400 error for malformed JSON', () => {
      expect(() => parseJsonBody('{"a":')).to.throw('Malformed JSON request body').with.property('status', 400)
    })
  })

  describe('genericErrorHandler', () => {
    let res: any
    let next: any
    const req: any = { method: 'GET', path: '/rest/x' }

    beforeEach(() => {
      res = { headersSent: false, statusCode: 200, status: sinon.stub(), type: sinon.stub(), send: sinon.stub() }
      res.status.returns(res)
      res.type.returns(res)
      next = sinon.spy()
      sinon.stub(logger, 'error')
    })

    afterEach(() => {
      sinon.restore()
    })

    it('responds with a generic 500 message without stack trace', () => {
      genericErrorHandler()(new Error('SQLITE_ERROR: near "x" at /app/routes/login.ts:42'), req, res, next)
      expect(res.status).to.have.been.calledWith(500)
      expect(res.type).to.have.been.calledWith('text/plain')
      expect(res.send).to.have.been.calledWith('Internal Server Error')
      expect(next.called).to.equal(false)
    })

    it('responds with 400 for malformed JSON bodies', () => {
      let error: unknown
      try { parseJsonBody('{') } catch (err) { error = err }
      genericErrorHandler()(error, req, res, next)
      expect(res.status).to.have.been.calledWith(400)
      expect(res.send).to.have.been.calledWith('Bad Request')
    })

    it('keeps an error status already set on the response', () => {
      res.statusCode = 403
      genericErrorHandler()(new Error('Only .md and .pdf files are allowed!'), req, res, next)
      expect(res.status).to.have.been.calledWith(403)
      expect(res.send).to.have.been.calledWith('Forbidden')
    })

    it('strips line breaks from the logged request path', () => {
      genericErrorHandler()(new Error('boom'), { method: 'GET', path: '/rest/x\r\nforged entry' }, res, next)
      expect((logger.error as sinon.SinonStub).firstCall.args[0]).to.match(/^GET \/rest\/xforged entry failed: /)
    })

    it('delegates when headers were already sent', () => {
      res.headersSent = true
      const err = new Error('late')
      genericErrorHandler()(err, req, res, next)
      expect(next).to.have.been.calledWith(err)
      expect(res.send.called).to.equal(false)
    })
  })
})
