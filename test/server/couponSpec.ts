/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { BasketModel } from '../../models/basket'
import * as security from '../../lib/insecurity'
import { applyCoupon } from '../../routes/coupon'

const expect = chai.expect
chai.use(sinonChai)

describe('coupon', () => {
  let req: any
  let res: any
  let next: any
  let basket: any

  beforeEach(() => {
    res = { json: sinon.spy(), status: sinon.stub(), send: sinon.spy() }
    res.status.returns(res)
    next = sinon.spy()
    basket = { update: sinon.stub().resolves() }
  })

  afterEach(() => {
    sinon.restore()
  })

  it('should apply valid coupon to basket and return its discount', async () => {
    sinon.stub(BasketModel, 'findByPk').resolves(basket)
    const coupon = security.generateCoupon(42)
    req = { params: { id: '1', coupon: encodeURIComponent(coupon) } }

    await applyCoupon()(req, res, next)

    expect(basket.update).to.have.been.calledWith({ coupon })
    expect(res.json).to.have.been.calledWith({ discount: 42 })
  })

  it('should reset coupon of basket and respond with 404 for invalid coupon', async () => {
    sinon.stub(BasketModel, 'findByPk').resolves(basket)
    req = { params: { id: '1', coupon: 'INVALID' } }

    await applyCoupon()(req, res, next)

    expect(basket.update).to.have.been.calledWith({ coupon: undefined })
    expect(res.status).to.have.been.calledWith(404)
    expect(res.send).to.have.been.calledWith('Invalid coupon.')
  })

  it('should reject expired coupon', async () => {
    sinon.stub(BasketModel, 'findByPk').resolves(basket)
    const expired = security.generateCoupon(42, new Date(2000, 0, 1))
    req = { params: { id: '1', coupon: expired } }

    await applyCoupon()(req, res, next)

    expect(res.status).to.have.been.calledWith(404)
  })

  it('should pass error to next when basket does not exist', async () => {
    sinon.stub(BasketModel, 'findByPk').resolves(null)
    req = { params: { id: '4711', coupon: security.generateCoupon(10) } }

    await applyCoupon()(req, res, next)

    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error).and(sinon.match.has('message', 'Basket with id=4711 does not exist.')))
    expect(res.json).to.have.not.been.calledWith(sinon.match.any)
  })

  it('should pass database errors to next', async () => {
    const error = new Error('DB down')
    sinon.stub(BasketModel, 'findByPk').rejects(error)
    req = { params: { id: '1' } }

    await applyCoupon()(req, res, next)

    expect(next).to.have.been.calledWith(error)
  })
})
