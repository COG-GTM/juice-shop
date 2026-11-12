/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import type { Challenge } from 'data/types'
import { saveLoginIp } from '../../routes/saveLoginIp'
import { authenticatedUsers } from '../../lib/insecurity'
import { challenges } from '../../data/datacache'
import { UserModel } from '../../models/user'
const expect = chai.expect
chai.use(sinonChai)

describe('saveLoginIp', () => {
  const token = 'saveLoginIpSpecToken'
  let req: any
  let res: any
  let next: any
  let update: sinon.SinonSpy

  beforeEach(() => {
    authenticatedUsers.put(token, { data: { id: 42 } } as any)
    challenges.httpHeaderXssChallenge = { solved: false, save: sinon.stub().resolves() } as unknown as Challenge
    update = sinon.spy(async (values: { lastLoginIp: string }) => values)
    sinon.stub(UserModel, 'findByPk').resolves({ update } as any)
    req = { headers: { authorization: `Bearer ${token}` }, socket: { remoteAddress: '::ffff:192.0.2.10' } }
    res = { json: sinon.spy(), sendStatus: sinon.spy() }
    next = sinon.spy()
  })

  afterEach(() => {
    sinon.restore()
  })

  it('stores a valid True-Client-IP sent by a trusted proxy', async () => {
    req.headers['true-client-ip'] = '203.0.113.7'

    await saveLoginIp(['192.0.2.10'])(req, res, next)

    expect(update).to.have.been.calledWith({ lastLoginIp: '203.0.113.7' })
    expect(res.json).to.have.been.calledWith({ lastLoginIp: '203.0.113.7' })
  })

  it('stores the proxy address when a trusted proxy sends a non-IP True-Client-IP', async () => {
    req.headers['true-client-ip'] = '<b>x</b>'

    await saveLoginIp(['192.0.2.0/24'])(req, res, next)

    expect(res.json).to.have.been.calledWith({ lastLoginIp: '192.0.2.10' })
  })

  it('stores the peer address when an untrusted peer sends a valid True-Client-IP', async () => {
    req.headers['true-client-ip'] = '203.0.113.7'

    await saveLoginIp(['198.51.100.1'])(req, res, next)

    expect(res.json).to.have.been.calledWith({ lastLoginIp: '192.0.2.10' })
  })

  it('stores the peer address when no proxies are configured', async () => {
    req.headers['true-client-ip'] = '203.0.113.7'

    await saveLoginIp()(req, res, next)

    expect(res.json).to.have.been.calledWith({ lastLoginIp: '192.0.2.10' })
  })

  it('responds 401 without an authenticated user', async () => {
    req.headers.authorization = undefined

    await saveLoginIp(['192.0.2.10'])(req, res, next)

    expect(res.sendStatus).to.have.been.calledWith(401)
    expect(update).to.have.callCount(0)
  })
})
