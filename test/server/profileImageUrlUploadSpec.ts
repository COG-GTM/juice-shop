/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
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
})
