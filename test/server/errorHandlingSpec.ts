/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { exposeErrorDetails, genericErrorHandler } from '../../lib/errorHandling'
import logger from '../../lib/logger'

const expect = chai.expect
chai.use(sinonChai)

describe('errorHandling', () => {
  describe('exposeErrorDetails', () => {
    it('is enabled for development and test environments', () => {
      expect(exposeErrorDetails({ NODE_ENV: 'development' })).to.equal(true)
      expect(exposeErrorDetails({ NODE_ENV: 'test' })).to.equal(true)
    })

    for (const env of [undefined, '', 'production', 'ctf', 'unsafe', 'Development']) {
      it(`is disabled for NODE_ENV=${String(env)}`, () => {
        expect(exposeErrorDetails({ NODE_ENV: env })).to.equal(false)
      })
    }
  })

  describe('genericErrorHandler', () => {
    let req: any
    let res: any
    let next: any
    let loggerError: sinon.SinonStub

    beforeEach(() => {
      req = { method: 'GET', path: '/rest/products/search', accepts: sinon.stub().returns('html') }
      res = { headersSent: false, statusCode: 200 }
      res.status = sinon.stub().returns(res)
      res.setHeader = sinon.stub().returns(res)
      res.end = sinon.stub().returns(res)
      next = sinon.spy()
      loggerError = sinon.stub(logger, 'error')
    })

    afterEach(() => {
      loggerError.restore()
    })

    it('responds with a generic 500 message without stack trace or error details', () => {
      const err = new Error('SQLITE_ERROR: near "\'": syntax error')

      genericErrorHandler()(err, req, res, next)

      expect(res.status).to.have.been.calledWith(500)
      expect(res.setHeader).to.have.been.calledWith('Content-Type', 'text/plain; charset=utf-8')
      expect(res.setHeader).to.have.been.calledWith('Content-Length', 21)
      expect(res.end).to.have.been.calledWith('Internal Server Error')
      expect(next).to.have.callCount(0)
    })

    it('logs error details server-side', () => {
      const err = new Error('SQLITE_ERROR: near "\'": syntax error')

      genericErrorHandler()(err, req, res, next)

      expect(loggerError).to.have.callCount(1)
      expect(loggerError.firstCall.args[0]).to.contain('GET /rest/products/search failed with 500')
      expect(loggerError.firstCall.args[0]).to.contain('SQLITE_ERROR')
      expect(loggerError.firstCall.args[0]).to.contain(err.stack)
    })

    it('keeps client error status codes from the error', () => {
      genericErrorHandler()(Object.assign(new Error('Blocked illegal activity'), { status: 403 }), req, res, next)

      expect(res.status).to.have.been.calledWith(403)
      expect(res.end).to.have.been.calledWith('Forbidden')
    })

    it('keeps a previously set error status code of the response', () => {
      res.statusCode = 404

      genericErrorHandler()(new Error('Basket with id=42 does not exist.'), req, res, next)

      expect(res.status).to.have.been.calledWith(404)
      expect(res.end).to.have.been.calledWith('Not Found')
    })

    it('falls back to 500 for non-error status codes', () => {
      genericErrorHandler()(Object.assign(new Error('weird'), { status: 302 }), req, res, next)

      expect(res.status).to.have.been.calledWith(500)
    })

    it('responds with generic JSON to clients preferring JSON', () => {
      req.accepts.returns('json')

      genericErrorHandler()(new Error('SQLITE_ERROR'), req, res, next)

      expect(res.setHeader).to.have.been.calledWith('Content-Type', 'application/json; charset=utf-8')
      expect(res.end).to.have.been.calledWith('{"error":{"status":500,"message":"Internal Server Error"}}')
    })

    it('passes the body to res.end as string so string-rewriting middleware keeps working', () => {
      genericErrorHandler()(new Error('boom'), req, res, next)

      expect(res.end.firstCall.args[0]).to.be.a('string')
    })

    it('strips line breaks from the logged request path', () => {
      req.path = '/foo\r\nINJECTED'

      genericErrorHandler()(new Error('boom'), req, res, next)

      expect(loggerError.firstCall.args[0]).to.contain('GET /fooINJECTED failed')
    })

    it('delegates to the next handler when headers were already sent', () => {
      res.headersSent = true
      const err = new Error('boom')

      genericErrorHandler()(err, req, res, next)

      expect(next).to.have.been.calledWith(err)
      expect(res.status).to.have.callCount(0)
    })
  })
})
