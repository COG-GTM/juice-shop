/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { UserModel } from '../../models/user'
import * as security from '../../lib/insecurity'
import retrieveUserList from '../../routes/authenticatedUsers'

const expect = chai.expect
chai.use(sinonChai)

describe('authenticatedUsers', () => {
  let req: any
  let res: any
  let next: any

  const userWith = (id: number, password: string, totpSecret: string) => ({
    id,
    password,
    totpSecret,
    dataValues: { id, email: `user${id}@juice-sh.op`, password, totpSecret }
  })

  beforeEach(() => {
    req = {}
    res = { json: sinon.spy() }
    next = sinon.spy()
  })

  afterEach(() => {
    sinon.restore()
  })

  it('should mask passwords and TOTP secrets of all users', async () => {
    sinon.stub(UserModel, 'findAll').resolves([userWith(4710, 'secret', 'IFTXE3SPOEYVURT2')] as any)

    await retrieveUserList()(req, res, next)

    const [user] = res.json.firstCall.args[0].data
    expect(res.json.firstCall.args[0].status).to.equal('success')
    expect(user.email).to.equal('user4710@juice-sh.op')
    expect(user.password).to.equal('******')
    expect(user.totpSecret).to.equal('****************')
  })

  it('should include last login time only for users with an active token', async () => {
    const token = security.authorize({ data: { id: 4711 } })
    security.authenticatedUsers.put(token, { data: { id: 4711 } } as any)
    sinon.stub(UserModel, 'findAll').resolves([userWith(4711, 'a', ''), userWith(4712, 'b', '')] as any)

    await retrieveUserList()(req, res, next)

    const [loggedIn, loggedOut] = res.json.firstCall.args[0].data
    expect(loggedIn.lastLoginTime).to.be.a('number')
    expect(loggedOut.lastLoginTime).to.equal(null)
  })

  it('should pass database errors to next', async () => {
    const error = new Error('DB down')
    sinon.stub(UserModel, 'findAll').rejects(error)

    await retrieveUserList()(req, res, next)

    expect(next).to.have.been.calledWith(error)
  })
})
