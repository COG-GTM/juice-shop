/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import sinon from 'sinon'
import config from 'config'
import sinonChai from 'sinon-chai'
import { challenges } from '../../data/datacache'
import type { Challenge } from 'data/types'
import * as security from '../../lib/insecurity'
import { UserModel } from '../../models/user'
import { saveLoginIp } from '../../routes/saveLoginIp'
const expect = chai.expect

chai.use(sinonChai)

describe('saveLoginIp', () => {
  const xssPayload = '<iframe src="javascript:alert(`xss`)">'
  let req: any
  let res: any
  let next: any
  let update: sinon.SinonStub
  let findByPk: sinon.SinonStub

  function disableHttpHeaderXssChallenge () {
    challenges.httpHeaderXssChallenge.disabledEnv = 'Docker'
    sinon.stub(config, 'get').callThrough().withArgs('challenges.safetyMode').returns('enabled')
  }

  beforeEach(() => {
    req = { headers: { authorization: 'Bearer token12345' }, socket: { remoteAddress: '::1' } }
    res = { json: sinon.spy(), sendStatus: sinon.spy() }
    next = sinon.spy()
    update = sinon.stub().callsFake(async (attributes: any) => attributes)
    findByPk = sinon.stub(UserModel, 'findByPk').resolves({ update } as unknown as UserModel)
    challenges.httpHeaderXssChallenge = { solved: false, save: () => ({ then () { } }) } as unknown as Challenge
    security.authenticatedUsers.put('token12345', {
      data: { id: 42, email: 'test@juice-sh.op' } as unknown as UserModel
    })
  })

  afterEach(() => {
    sinon.restore()
  })

  it('saves the "true-client-ip" header as last login IP', async () => {
    req.headers['true-client-ip'] = '1.2.3.4'

    await saveLoginIp()(req, res, next)

    expect(findByPk).to.have.been.calledWith(42)
    expect(update).to.have.been.calledWith({ lastLoginIp: '1.2.3.4' })
    expect(res.json).to.have.been.calledWith({ lastLoginIp: '1.2.3.4' })
  })

  it('saves the first value of a repeated "true-client-ip" header as last login IP', async () => {
    req.headers['true-client-ip'] = ['1.2.3.4', '5.6.7.8']

    await saveLoginIp()(req, res, next)

    expect(update).to.have.been.calledWith({ lastLoginIp: '1.2.3.4' })
  })

  it('saves the remote address as last login IP when no "true-client-ip" header is present', async () => {
    await saveLoginIp()(req, res, next)

    expect(update).to.have.been.calledWith({ lastLoginIp: '127.0.0.1' })
  })

  it('saves an IPv4-mapped remote address in its simple form as last login IP', async () => {
    req.socket.remoteAddress = '::ffff:10.0.0.1'

    await saveLoginIp()(req, res, next)

    expect(update).to.have.been.calledWith({ lastLoginIp: '10.0.0.1' })
  })

  it('solves the "httpHeaderXssChallenge" when the XSS payload is passed as "true-client-ip" header', async () => {
    req.headers['true-client-ip'] = xssPayload

    await saveLoginIp()(req, res, next)

    expect(challenges.httpHeaderXssChallenge.solved).to.equal(true)
    expect(update).to.have.been.calledWith({ lastLoginIp: xssPayload })
  })

  it('does not solve the "httpHeaderXssChallenge" for a harmless "true-client-ip" header', async () => {
    req.headers['true-client-ip'] = '1.2.3.4'

    await saveLoginIp()(req, res, next)

    expect(challenges.httpHeaderXssChallenge.solved).to.equal(false)
  })

  it('sanitizes the "true-client-ip" header when the "httpHeaderXssChallenge" is disabled', async () => {
    disableHttpHeaderXssChallenge()
    req.headers['true-client-ip'] = '<script>alert(1)</script>1.2.3.4'

    await saveLoginIp()(req, res, next)

    expect(update).to.have.been.calledWith({ lastLoginIp: '1.2.3.4' })
    expect(challenges.httpHeaderXssChallenge.solved).to.equal(false)
  })

  it('forwards errors while updating the user to the error handler', async () => {
    const error = new Error('DB unavailable')
    findByPk.rejects(error)

    await saveLoginIp()(req, res, next)

    expect(next).to.have.been.calledWith(error)
    expect(res.json).to.have.callCount(0)
  })

  it('returns 401 for a request without a valid authentication token', async () => {
    req.headers.authorization = 'Bearer unknown-token'

    await saveLoginIp()(req, res, next)

    expect(res.sendStatus).to.have.been.calledWith(401)
    expect(findByPk).to.have.callCount(0)
  })
})
