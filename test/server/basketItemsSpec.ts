/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { BasketItemModel } from '../../models/basketitem'
import { QuantityModel } from '../../models/quantity'
import { quantityCheckBeforeBasketItemUpdate } from '../../routes/basketItems'
const expect = chai.expect
chai.use(sinonChai)

describe('basketItems', () => {
  describe('quantityCheckBeforeBasketItemUpdate', () => {
    let req: any
    let res: any
    let next: any

    beforeEach(() => {
      req = { params: { id: 1 }, body: { quantity: 1 }, headers: {}, cookies: {} }
      res = { status: sinon.stub().returnsThis(), json: sinon.spy(), __: (message: string) => message }
      next = sinon.spy()
      sinon.stub(BasketItemModel, 'findOne').resolves({ ProductId: 42 } as any)
    })

    afterEach(() => {
      sinon.restore()
    })

    it('passes a missing quantity record on to the error handler', async () => {
      sinon.stub(QuantityModel, 'findOne').resolves(null)

      await quantityCheckBeforeBasketItemUpdate()(req, res, next)

      expect(next).to.have.been.calledOnceWith(sinon.match.instanceOf(Error).and(sinon.match.has('message', 'No such product found!')))
    })

    it('passes a failing quantity lookup on to the error handler', async () => {
      const error = new Error('SQLITE_BUSY')
      sinon.stub(QuantityModel, 'findOne').rejects(error)

      await quantityCheckBeforeBasketItemUpdate()(req, res, next)

      expect(next).to.have.been.calledOnceWith(error)
    })

    it('calls next without error when enough stock is available', async () => {
      sinon.stub(QuantityModel, 'findOne').resolves({ quantity: 5, limitPerUser: null } as any)

      await quantityCheckBeforeBasketItemUpdate()(req, res, next)

      expect(next).to.have.been.calledOnceWithExactly()
    })

    it('rejects the update when stock is insufficient', async () => {
      req.body.quantity = 10
      sinon.stub(QuantityModel, 'findOne').resolves({ quantity: 5, limitPerUser: null } as any)

      await quantityCheckBeforeBasketItemUpdate()(req, res, next)

      expect(res.status).to.have.been.calledWith(400)
      expect(next).to.have.callCount(0)
    })

    it('rejects updates of attributes other than quantity', async () => {
      req.body = { ProductId: 999999 }
      const quantityLookup = sinon.stub(QuantityModel, 'findOne')

      await quantityCheckBeforeBasketItemUpdate()(req, res, next)

      expect(res.status).to.have.been.calledWith(400)
      expect(res.json).to.have.been.calledWith({ error: 'Only the quantity of a basket item can be updated.' })
      expect(quantityLookup).to.have.callCount(0)
      expect(next).to.have.callCount(0)
    })

    it('allows the user ID appended by the authorization middleware', async () => {
      req.body = { quantity: 1, UserId: 1 }
      sinon.stub(QuantityModel, 'findOne').resolves({ quantity: 5, limitPerUser: null } as any)

      await quantityCheckBeforeBasketItemUpdate()(req, res, next)

      expect(next).to.have.been.calledOnceWithExactly()
    })
  })
})
