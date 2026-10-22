/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { type Challenge } from 'data/types'
import { challenges } from '../../data/datacache'
import * as security from '../../lib/insecurity'
import { UserModel } from '../../models/user'
import { updateUserProfile } from '../../routes/updateUserProfile'

const expect = chai.expect
chai.use(sinonChai)

describe('updateUserProfile', () => {
  let req: any
  let res: any
  let next: any
  let save: any

  beforeEach(() => {
    const user: any = {
      username: 'old',
      update: sinon.stub().callsFake(async ({ username }) => ({ id: 1, email: 'test@juice-sh.op', username }))
    }
    sinon.stub(UserModel, 'findByPk').resolves(user)
    sinon.stub(security.authenticatedUsers, 'get').returns({ data: { id: 1 } } as any)
    sinon.stub(security.authenticatedUsers, 'put')
    save = () => ({ then () { } })
    challenges.csrfChallenge = { solved: false, save } as unknown as Challenge
    req = { cookies: { token: 'token' }, headers: {}, body: { username: 'CSRF' }, socket: {} }
    res = { cookie: sinon.spy(), location: sinon.spy(), redirect: sinon.spy() }
    next = sinon.spy()
  })

  afterEach(() => {
    sinon.restore()
  })

  it('should solve "csrfChallenge" for a request from htmledit.squarefree.com', async () => {
    req.headers.origin = 'http://htmledit.squarefree.com'

    await updateUserProfile()(req, res, next)

    expect(challenges.csrfChallenge.solved).to.equal(true)
    expect(res.redirect).to.have.been.calledWith(sinon.match(/\/profile$/))
  })

  it('should solve "csrfChallenge" based on the Referer when no Origin is sent', async () => {
    req.headers.referer = 'https://htmledit.squarefree.com/'

    await updateUserProfile()(req, res, next)

    expect(challenges.csrfChallenge.solved).to.equal(true)
  })

  it('should not solve "csrfChallenge" when htmledit.squarefree.com only appears inside another URL', async () => {
    req.headers.origin = 'http://htmledit.squarefree.com.evil.com'
    req.headers.referer = 'http://evil.com/?://htmledit.squarefree.com'

    await updateUserProfile()(req, res, next)

    expect(challenges.csrfChallenge.solved).to.equal(false)
    expect(res.redirect).to.have.been.calledWith(sinon.match(/\/profile$/))
  })

  it('should not solve "csrfChallenge" via a substring match in the Referer', async () => {
    req.headers.referer = 'http://evil.com/://htmledit.squarefree.com'

    await updateUserProfile()(req, res, next)

    expect(challenges.csrfChallenge.solved).to.equal(false)
  })
})
