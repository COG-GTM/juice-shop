/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import * as security from '../../lib/insecurity'
import { profileImageUrlUpload } from '../../routes/profileImageUrlUpload'

const expect = chai.expect

describe('profileImageUrlUpload', () => {
  it('should not flag the SSRF challenge for unauthenticated requests', async () => {
    const req: any = {
      body: { imageUrl: 'http://localhost:3000/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3' },
      cookies: { token: 'unknown' },
      socket: { remoteAddress: '127.0.0.1' },
      app: { locals: { abused_ssrf_bug: false } }
    }
    let error: unknown
    await profileImageUrlUpload()(req, {} as any, (err?: unknown) => { error = err })

    expect(error).to.be.an('error')
    expect(req.app.locals.abused_ssrf_bug).to.equal(false)
  })
  it('should not flag the SSRF challenge when an authenticated user submits a rejected internal URL', async () => {
    security.authenticatedUsers.put('ssrf-spec-token', { data: { id: 4711 } } as any)
    const req: any = {
      body: { imageUrl: 'http://127.0.0.1:3000/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3' },
      cookies: { token: 'ssrf-spec-token' },
      socket: { remoteAddress: '127.0.0.1' },
      app: { locals: { abused_ssrf_bug: false } }
    }
    let redirected = false
    const res: any = { location: () => {}, redirect: () => { redirected = true } }
    let error: unknown
    await profileImageUrlUpload()(req, res, (err?: unknown) => { error = err })

    expect(error).to.equal(undefined)
    expect(redirected).to.equal(true)
    expect(req.app.locals.abused_ssrf_bug).to.equal(false)
  })
})
