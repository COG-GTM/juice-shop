/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import sinon from 'sinon'
import sinonChai from 'sinon-chai'
import { BasketModel } from '../../models/basket'
import { retrieveBasket } from '../../routes/basket'
const expect = chai.expect
chai.use(sinonChai)

describe('basket', () => {
  let req: any
  let res: any
  let next: any
  let findOne: sinon.SinonStub

  beforeEach(() => {
    req = { params: { id: '2' }, body: { UserId: 2 }, headers: {}, __: (s: string) => s }
    res = { json: sinon.spy(), status: sinon.stub() }
    res.status.returns(res)
    next = sinon.spy()
    findOne = sinon.stub(BasketModel, 'findOne')
  })

  afterEach(() => {
    findOne.restore()
  })

  it('looks up the basket by id and the authenticated user id', async () => {
    findOne.resolves({ id: 2, UserId: 2, Products: [] })

    await retrieveBasket()(req, res, next)

    expect(findOne.firstCall.args[0].where).to.deep.equal({ id: '2', UserId: 2 })
    expect(res.status).not.to.have.been.called
    expect(res.json).to.have.been.calledOnce
  })

  it('returns 404 when the basket belongs to another user', async () => {
    req.params.id = '1'
    findOne.resolves(null)

    await retrieveBasket()(req, res, next)

    expect(findOne.firstCall.args[0].where).to.deep.equal({ id: '1', UserId: 2 })
    expect(res.status).to.have.been.calledWith(404)
    expect(res.json).to.have.been.calledWith({ status: 'error', error: 'Basket not found' })
    expect(next).not.to.have.been.called
  })
})
