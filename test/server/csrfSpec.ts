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

  function withHeaders (method: string, headers: Record<string, string>, trustProxy = false) {
    const lowerCased = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]))
    return {
      method,
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
    expect(res.status).to.have.not.been.called
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
    expect(next).to.have.not.been.called
  })

  it('rejects cross-site POST by Referer', () => {
    req = withHeaders('POST', { host: 'localhost:3000', referer: 'https://evil.example/csrf.html' })
    csrfProtection()(req, res, next)
    expect(res.status).to.have.been.calledWith(403)
    expect(next).to.have.not.been.called
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
    req = withHeaders('POST', { host: 'juice-shop:3000', 'x-forwarded-host': 'shop.example', origin: 'https://shop.example' }, true)
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

  it('passes cross-origin POST authenticated by Bearer token instead of cookies', () => {
    req = withHeaders('POST', { host: 'localhost:3000', origin: 'http://localhost:4200', authorization: 'Bearer eyJ' })
    csrfProtection()(req, res, next)
    expect(next).to.have.been.calledWith()
  })
})
