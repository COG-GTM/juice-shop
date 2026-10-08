/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import config from 'config'
import logger from '../../lib/logger'
import { corsAllowedOrigins, corsOptions, exposeErrorDetails, genericErrorHandler, loadCookieParserSecret } from '../../lib/httpHardening'

const expect = chai.expect
chai.use(sinonChai)

describe('httpHardening', () => {
  describe('loadCookieParserSecret', () => {
    it('uses COOKIE_PARSER_SECRET from the environment', () => {
      expect(loadCookieParserSecret({ COOKIE_PARSER_SECRET: 's3cr3t' })).to.equal('s3cr3t')
    })

    it('falls back to a random secret instead of a hardcoded one', () => {
      const first = loadCookieParserSecret({})
      const second = loadCookieParserSecret({ COOKIE_PARSER_SECRET: ' ' })
      expect(first).to.match(/^[0-9a-f]{64}$/)
      expect(second).to.match(/^[0-9a-f]{64}$/)
      expect(first).to.not.equal(second)
      expect(first).to.not.equal('kekse')
    })
  })

  describe('corsAllowedOrigins', () => {
    it('defaults to the configured base URL and the Angular dev server origins', () => {
      expect(corsAllowedOrigins({})).to.deep.equal([config.get<string>('server.baseUrl'), 'http://localhost:4200', 'http://127.0.0.1:4200'])
    })

    it('trusts only the configured base URL by default in production', () => {
      expect(corsAllowedOrigins({ NODE_ENV: 'production' })).to.deep.equal([config.get<string>('server.baseUrl')])
    })

    it('reads a comma-separated list from CORS_ALLOWED_ORIGINS', () => {
      expect(corsAllowedOrigins({ CORS_ALLOWED_ORIGINS: ' https://a.example/ , ,https://b.example' })).to.deep.equal(['https://a.example', 'https://b.example'])
    })
  })

  describe('corsOptions', () => {
    const decide = (origin: string | undefined) => {
      const callback = sinon.spy()
      const originFn = corsOptions(['https://shop.example']).origin as (origin: string | undefined, cb: (err: Error | null, allow?: boolean) => void) => void
      originFn(origin, callback)
      return callback.firstCall.args[1]
    }

    it('allows listed origins', () => {
      expect(decide('https://shop.example')).to.equal(true)
    })

    it('rejects unlisted origins', () => {
      expect(decide('https://attacker.example')).to.equal(false)
      expect(decide('null')).to.equal(false)
    })

    it('sends no CORS header for same-origin requests without Origin', () => {
      expect(decide(undefined)).to.equal(false)
    })
  })

  describe('exposeErrorDetails', () => {
    it('is disabled only in production', () => {
      expect(exposeErrorDetails({ NODE_ENV: 'production' })).to.equal(false)
      expect(exposeErrorDetails({ NODE_ENV: 'development' })).to.equal(true)
      expect(exposeErrorDetails({ NODE_ENV: 'test' })).to.equal(true)
      expect(exposeErrorDetails({ NODE_ENV: 'tutorial' })).to.equal(true)
      expect(exposeErrorDetails({})).to.equal(true)
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
      expect(next).to.not.have.been.called
    })

    it('preserves client error status codes', () => {
      genericErrorHandler()(Object.assign(new Error('jwt malformed'), { status: 401 }), req, res, next)
      expect(res.status).to.have.been.calledWith(401)
      expect(res.send).to.have.been.calledWith('Unauthorized')
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

    it('maps invalid status codes to 500', () => {
      genericErrorHandler()(Object.assign(new Error('weird'), { statusCode: 200 }), req, res, next)
      expect(res.status).to.have.been.calledWith(500)
    })

    it('delegates when headers were already sent', () => {
      res.headersSent = true
      const err = new Error('late')
      genericErrorHandler()(err, req, res, next)
      expect(next).to.have.been.calledWith(err)
      expect(res.send).to.not.have.been.called
    })
  })
})
