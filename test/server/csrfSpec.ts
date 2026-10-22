/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { csrfProtection } from '../../lib/csrf'

const expect = chai.expect
chai.use(sinonChai)

describe('csrfProtection', () => {
  let req: any
  let res: any
  let next: any

  function withHeaders (method: string, headers: Record<string, string>, trustProxy = false, protocol = 'http', cookie: string | null = 'token=eyJ') {
    const lowerCased: Record<string, string> = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]))
    if (cookie !== null) {
      lowerCased.cookie = cookie
    }
    return {
      method,
      protocol,
      app: { enabled: (setting: string) => setting === 'trust proxy' && trustProxy },
      get: (name: string) => lowerCased[name.toLowerCase()]
    }
  }

  beforeEach(() => {
    res = { status: sinon.stub().returnsThis(), json: sinon.spy() }
    next = sinon.spy()
  })

  it('passes same-origin POST with matching Origin', () => {
    req = withHeaders('POST', { host: 'localhost:3000', origin: 'http://localhost:3000' })
    csrfProtection()(req, res, next)
    expect(next).to.have.been.calledWith()
    expect(res.status.called).to.equal(false)
  })

  it('passes same-origin POST with matching Referer', () => {
    req = withHeaders('POST', { host: 'localhost:3000', referer: 'http://localhost:3000/profile' })
    csrfProtection()(req, res, next)
    expect(next).to.have.been.calledWith()
  })

  it('passes POST without Origin and Referer from non-browser clients', () => {
    req = withHeaders('POST', { host: 'localhost:3000' })
    csrfProtection()(req, res, next)
    expect(next).to.have.been.calledWith()
  })

  it('rejects cross-site POST by Origin', () => {
    req = withHeaders('POST', { host: 'localhost:3000', origin: 'http://htmledit.squarefree.com' })
    csrfProtection()(req, res, next)
    expect(res.status).to.have.been.calledWith(403)
    expect(next.called).to.equal(false)
  })

  it('rejects cross-site POST by Referer', () => {
    req = withHeaders('POST', { host: 'localhost:3000', referer: 'https://evil.example/csrf.html' })
    csrfProtection()(req, res, next)
    expect(res.status).to.have.been.calledWith(403)
    expect(next.called).to.equal(false)
  })

  it('rejects opaque "null" Origin', () => {
    req = withHeaders('POST', { host: 'localhost:3000', origin: 'null' })
    csrfProtection()(req, res, next)
    expect(res.status).to.have.been.calledWith(403)
  })

  it('rejects same host on a different port', () => {
    req = withHeaders('POST', { host: 'localhost:3000', origin: 'http://localhost:8080' })
    csrfProtection()(req, res, next)
    expect(res.status).to.have.been.calledWith(403)
  })

  it('uses X-Forwarded-Host when trust proxy is enabled', () => {
    req = withHeaders('POST', { host: 'juice-shop:3000', 'x-forwarded-host': 'shop.example', origin: 'https://shop.example' }, true, 'https')
    csrfProtection()(req, res, next)
    expect(next).to.have.been.calledWith()
  })

  it('ignores X-Forwarded-Host when trust proxy is disabled', () => {
    req = withHeaders('POST', { host: 'juice-shop:3000', 'x-forwarded-host': 'evil.example', origin: 'https://evil.example' })
    csrfProtection()(req, res, next)
    expect(res.status).to.have.been.calledWith(403)
  })

  it('passes safe methods regardless of Origin', () => {
    req = withHeaders('GET', { host: 'localhost:3000', origin: 'https://evil.example' })
    csrfProtection()(req, res, next)
    expect(next).to.have.been.calledWith()
  })

  it('rejects same host with a different scheme', () => {
    req = withHeaders('POST', { host: 'shop.example', origin: 'http://shop.example' }, false, 'https')
    csrfProtection()(req, res, next)
    expect(res.status).to.have.been.calledWith(403)
  })

  it('passes HTTPS origin behind a TLS-terminating proxy that omits X-Forwarded-Proto', () => {
    req = withHeaders('POST', { host: 'shop.example', origin: 'https://shop.example' }, false, 'http')
    csrfProtection()(req, res, next)
    expect(next).to.have.been.calledWith()
  })

  it('rejects cross-site POST with cookie even when a Bearer header is present', () => {
    req = withHeaders('POST', { host: 'localhost:3000', origin: 'https://evil.example', authorization: 'Bearer forged' })
    csrfProtection()(req, res, next)
    expect(res.status).to.have.been.calledWith(403)
    expect(next.called).to.equal(false)
  })

  it('passes cross-origin POST without cookies from the Angular dev server', () => {
    req = withHeaders('POST', { host: 'localhost:3000', origin: 'http://localhost:4200' }, false, 'http', null)
    csrfProtection()(req, res, next)
    expect(next).to.have.been.calledWith()
  })
})
