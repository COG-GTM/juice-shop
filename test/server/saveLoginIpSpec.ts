/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { type Challenge } from 'data/types'
import { challenges } from '../../data/datacache'
import { UserModel } from '../../models/user'
import * as security from '../../lib/insecurity'
import { saveLoginIp } from '../../routes/saveLoginIp'

const expect = chai.expect
chai.use(sinonChai)

describe('saveLoginIp', () => {
  const originalChallenges = { ...challenges }

  after(() => {
    for (const key of Object.keys(challenges)) {
      delete challenges[key]
    }
    Object.assign(challenges, originalChallenges)
  })

  const token = 'saveLoginIpSpecToken'
  let req: any
  let res: any
  let next: any
  let save: any
  let user: any

  before(() => {
    security.authenticatedUsers.put(token, { data: { id: 3 } } as any)
  })

  beforeEach(() => {
    req = { headers: { authorization: `Bearer ${token}` }, socket: { remoteAddress: '::ffff:192.168.0.1' } }
    res = { json: sinon.spy(), sendStatus: sinon.spy() }
    next = sinon.spy()
    save = () => ({
      then () { }
    })
    user = { update: sinon.stub().callsFake(async (values: any) => values) }
    challenges.httpHeaderXssChallenge = { solved: false, save } as unknown as Challenge
  })

  afterEach(() => {
    sinon.restore()
  })

  it('should respond with 401 when no user is logged in', async () => {
    req.headers = {}

    await saveLoginIp()(req, res, next)

    expect(res.sendStatus).to.have.been.calledWith(401)
  })

  it('should store IP from True-Client-IP header as last login IP', async () => {
    const findByPk = sinon.stub(UserModel, 'findByPk').resolves(user)
    req.headers['true-client-ip'] = '10.0.0.1'

    await saveLoginIp()(req, res, next)

    expect(findByPk).to.have.been.calledWith(3)
    expect(user.update).to.have.been.calledWith({ lastLoginIp: '10.0.0.1' })
    expect(res.json).to.have.been.calledWith({ lastLoginIp: '10.0.0.1' })
  })

  it('should use first value of multi-valued True-Client-IP header', async () => {
    sinon.stub(UserModel, 'findByPk').resolves(user)
    req.headers['true-client-ip'] = ['10.0.0.2', '10.0.0.3']

    await saveLoginIp()(req, res, next)

    expect(user.update).to.have.been.calledWith({ lastLoginIp: '10.0.0.2' })
  })

  it('should fall back to remote address of socket without True-Client-IP header', async () => {
    sinon.stub(UserModel, 'findByPk').resolves(user)

    await saveLoginIp()(req, res, next)

    expect(user.update).to.have.been.calledWith({ lastLoginIp: '192.168.0.1' })
  })

  it('should solve "httpHeaderXssChallenge" for the expected XSS payload', async () => {
    sinon.stub(UserModel, 'findByPk').resolves(user)
    req.headers['true-client-ip'] = '<iframe src="javascript:alert(`xss`)">'

    await saveLoginIp()(req, res, next)

    expect(challenges.httpHeaderXssChallenge.solved).to.equal(true)
  })

  it('should not solve "httpHeaderXssChallenge" for other header values', async () => {
    sinon.stub(UserModel, 'findByPk').resolves(user)
    req.headers['true-client-ip'] = '<script>alert(1)</script>'

    await saveLoginIp()(req, res, next)

    expect(challenges.httpHeaderXssChallenge.solved).to.equal(false)
  })

  it('should pass database errors to next', async () => {
    const error = new Error('DB down')
    sinon.stub(UserModel, 'findByPk').rejects(error)

    await saveLoginIp()(req, res, next)

    expect(next).to.have.been.calledWith(error)
  })
})
