/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import config from 'config'
import logger from '../../lib/logger'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { angularClientCsp, contentSecurityPolicy, corsAllowedOrigins, cspHeaderName, corsOptions, exposeErrorDetails, genericErrorHandler, inlineScriptHashes } from '../../lib/httpHardening'

const expect = chai.expect
chai.use(sinonChai)

describe('httpHardening', () => {
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

    it('never allows the wildcard or the null origin', () => {
      expect(corsAllowedOrigins({ CORS_ALLOWED_ORIGINS: '*,null,https://a.example' })).to.deep.equal(['https://a.example'])
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

  describe('inlineScriptHashes', () => {
    const hash = (text: string) => `'sha256-${crypto.createHash('sha256').update(text).digest('base64')}'`

    it('hashes the exact body of inline JavaScript blocks', () => {
      const body = '\n    window.addEventListener("load", function () {})\n  '
      expect(inlineScriptHashes(`<head><script>${body}</script><script type="module">import "./a.js"</script></head>`).scripts)
        .to.deep.equal([hash(body), hash('import "./a.js"')])
    })

    it('ignores external scripts and non-JavaScript data blocks', () => {
      expect(inlineScriptHashes('<script src="main.js"></script><script type="text/vtt">WEBVTT</script><script type="application/json">{}</script>').scripts).to.deep.equal([])
    })

    it('hashes inline event handlers in markup but not inside script bodies', () => {
      const html = '<link rel="stylesheet" href="styles.css" media="print" onload="this.media=\'all\'"><script>var s = \'<img onerror="evil()">\'</script><img src=x onerror=\'a(&quot;b&quot;)\'>'
      expect(inlineScriptHashes(html).handlers).to.deep.equal([hash('this.media=\'all\''), hash('a("b")')])
    })
  })

  describe('contentSecurityPolicy', () => {
    const directive = (policy: string, name: string) => policy.split('; ').find(d => d.startsWith(`${name} `))

    it('restricts scripts to self without unsafe-inline or unsafe-eval', () => {
      const policy = contentSecurityPolicy()
      expect(directive(policy, 'default-src')).to.equal("default-src 'self'")
      expect(directive(policy, 'script-src')).to.not.match(/'unsafe-inline'|'unsafe-eval'|\*/)
      expect(directive(policy, 'object-src')).to.equal("object-src 'none'")
      expect(directive(policy, 'base-uri')).to.equal("base-uri 'self'")
      expect(directive(policy, 'frame-ancestors')).to.equal("frame-ancestors 'self'")
    })

    it('allows hashed inline scripts and only adds unsafe-hashes for event handlers', () => {
      expect(directive(contentSecurityPolicy({ scripts: ["'sha256-A='"], handlers: [] }), 'script-src')).to.match(/^script-src 'self' 'sha256-A=' /)
      expect(directive(contentSecurityPolicy({ scripts: ["'sha256-A='"], handlers: [] }), 'script-src')).to.not.include("'unsafe-hashes'")
      expect(directive(contentSecurityPolicy({ scripts: [], handlers: ["'sha256-B='"] }), 'script-src')).to.include("'unsafe-hashes' 'sha256-B='")
    })
  })

  describe('cspHeaderName', () => {
    it('enforces the policy in production or when CSP_ENFORCE is set', () => {
      expect(cspHeaderName({ NODE_ENV: 'production' })).to.equal('Content-Security-Policy')
      expect(cspHeaderName({ NODE_ENV: 'test', CSP_ENFORCE: 'true' })).to.equal('Content-Security-Policy')
    })

    it('only reports violations in training modes so XSS challenges stay solvable', () => {
      expect(cspHeaderName({ NODE_ENV: 'test' })).to.equal('Content-Security-Policy-Report-Only')
      expect(cspHeaderName({})).to.equal('Content-Security-Policy-Report-Only')
    })
  })

  describe('angularClientCsp', () => {
    let dir: string
    let indexFile: string

    beforeEach(() => {
      dir = fs.mkdtempSync(path.join(os.tmpdir(), 'csp-'))
      indexFile = path.join(dir, 'index.html')
    })

    afterEach(() => {
      fs.rmSync(dir, { recursive: true, force: true })
    })

    const policyFor = (middleware: ReturnType<typeof angularClientCsp>) => {
      const res = { setHeader: sinon.spy() }
      const next = sinon.spy()
      middleware({} as any, res as any, next)
      expect(next).to.have.been.calledOnce
      expect(res.setHeader.firstCall.args[0]).to.equal(cspHeaderName())
      return res.setHeader.firstCall.args[1] as string
    }

    it('allows the inline scripts of the served index.html and picks up later customizations', () => {
      fs.writeFileSync(indexFile, '<script>a()</script>')
      const middleware = angularClientCsp(indexFile)
      expect(policyFor(middleware)).to.include(inlineScriptHashes('<script>a()</script>').scripts[0])
      fs.writeFileSync(indexFile, '<script>customized()</script>')
      fs.utimesSync(indexFile, new Date(), new Date(Date.now() + 5000))
      const policy = policyFor(middleware)
      expect(policy).to.include(inlineScriptHashes('<script>customized()</script>').scripts[0])
      expect(policy).to.not.include(inlineScriptHashes('<script>a()</script>').scripts[0])
    })

    it('falls back to the base policy when there is no frontend build', () => {
      expect(policyFor(angularClientCsp(path.join(dir, 'missing.html')))).to.equal(contentSecurityPolicy())
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
      expect(next.called).to.equal(false)
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
      expect(res.send.called).to.equal(false)
    })
  })
})
