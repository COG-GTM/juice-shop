/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import sinon from 'sinon'
import sinonChai from 'sinon-chai'
import { restrictRegistrationAttributes } from '../../routes/userRegistration'
const expect = chai.expect

chai.use(sinonChai)

describe('userRegistration', () => {
  let res: any
  let next: any

  beforeEach(() => {
    res = {}
    next = sinon.spy()
  })

  it('keeps only the registration form attributes', () => {
    const securityQuestion = { id: 1, question: 'Your eldest siblings middle name?' }
    const req: any = {
      body: {
        email: 'jim@juice-sh.op',
        password: 'ncc-1701',
        passwordRepeat: 'ncc-1701',
        securityQuestion,
        securityAnswer: 'Samuel',
        id: 1,
        role: 'admin',
        deluxeToken: 'forged',
        totpSecret: 'IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH',
        isActive: false,
        profileImage: '/assets/public/images/uploads/defaultAdmin.png',
        lastLoginIp: '127.0.0.1',
        username: 'jim'
      }
    }

    restrictRegistrationAttributes()(req, res, next)

    expect(req.body).to.deep.equal({
      email: 'jim@juice-sh.op',
      password: 'ncc-1701',
      passwordRepeat: 'ncc-1701',
      securityQuestion,
      securityAnswer: 'Samuel'
    })
    expect(next).to.have.been.calledWith()
  })

  it('does not add attributes missing from the request', () => {
    const req: any = { body: { email: 'horst@horstma.nn', password: 'hooooorst', role: 'deluxe' } }

    restrictRegistrationAttributes()(req, res, next)

    expect(req.body).to.deep.equal({ email: 'horst@horstma.nn', password: 'hooooorst' })
  })

  it('replaces non-object bodies with an empty object', () => {
    for (const body of [undefined, null, 'role=admin', [{ role: 'admin' }]]) {
      const req: any = { body }

      restrictRegistrationAttributes()(req, res, next)

      expect(req.body).to.deep.equal({})
    }
    expect(next).to.have.callCount(4)
  })
})
