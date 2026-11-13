/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { profileImageUrlUpload } from '../../routes/profileImageUrlUpload'

const expect = chai.expect
chai.use(sinonChai)

describe('profileImageUrlUpload', () => {
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    req = { body: {}, cookies: {}, socket: { remoteAddress: '127.0.0.1' }, app: { locals: {} } }
    res = { location: sinon.spy(), redirect: sinon.spy() }
    next = sinon.spy()
  })

  it('should flag SSRF abuse for URLs containing the server-side challenge path', async () => {
    req.body.imageUrl = 'http://localhost:3000/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3'

    await profileImageUrlUpload()(req, res, next)

    expect(req.app.locals.abused_ssrf_bug).to.equal(true)
  })

  it('should not flag SSRF abuse for other URLs', async () => {
    req.body.imageUrl = 'https://example.com/avatar.png'

    await profileImageUrlUpload()(req, res, next)

    expect(req.app.locals.abused_ssrf_bug).to.equal(undefined)
  })

  it('should not flag SSRF abuse for non-string image URLs', async () => {
    req.body.imageUrl = ['solve/challenges/server-side']

    await profileImageUrlUpload()(req, res, next)

    expect(req.app.locals.abused_ssrf_bug).to.equal(undefined)
  })

  it('should process a long non-matching URL from an anonymous user in linear time', async () => {
    req.body.imageUrl = 'a'.repeat(100000)
    const start = Date.now()

    await profileImageUrlUpload()(req, res, next)

    expect(Date.now() - start).to.be.below(1000)
    expect(req.app.locals.abused_ssrf_bug).to.equal(undefined)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })
})
