/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { WalletModel } from '../../models/wallet'
import { CardModel } from '../../models/card'
import { getWalletBalance, addWalletBalance } from '../../routes/wallet'

const expect = chai.expect
chai.use(sinonChai)

describe('wallet', () => {
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    res = { json: sinon.spy(), status: sinon.stub() }
    res.status.returns(res)
    next = sinon.spy()
  })

  afterEach(() => {
    sinon.restore()
  })

  describe('getWalletBalance', () => {
    it('should return balance of the user\'s wallet', async () => {
      const findOne = sinon.stub(WalletModel, 'findOne').resolves({ balance: 100 } as any)
      req = { body: { UserId: 1 } }

      await getWalletBalance()(req, res, next)

      expect(findOne).to.have.been.calledWith({ where: { UserId: 1 } })
      expect(res.status).to.have.been.calledWith(200)
      expect(res.json).to.have.been.calledWith({ status: 'success', data: 100 })
    })

    it('should respond with 404 when user has no wallet', async () => {
      sinon.stub(WalletModel, 'findOne').resolves(null)
      req = { body: { UserId: 42 } }

      await getWalletBalance()(req, res, next)

      expect(res.status).to.have.been.calledWith(404)
      expect(res.json).to.have.been.calledWith({ status: 'error' })
    })
  })

  describe('addWalletBalance', () => {
    it('should top up wallet when paying with one of the user\'s own cards', async () => {
      const findCard = sinon.stub(CardModel, 'findOne').resolves({ id: 3 } as any)
      const increment = sinon.stub(WalletModel, 'increment').resolves()
      req = { body: { UserId: 1, paymentId: 3, balance: 50 } }

      await addWalletBalance()(req, res, next)

      expect(findCard).to.have.been.calledWith({ where: { id: 3, UserId: 1 } })
      expect(increment).to.have.been.calledWith({ balance: 50 }, { where: { UserId: 1 } })
      expect(res.status).to.have.been.calledWith(200)
      expect(res.json).to.have.been.calledWith({ status: 'success', data: 50 })
    })

    it('should reject payment when card does not belong to user', async () => {
      sinon.stub(CardModel, 'findOne').resolves(null)
      const increment = sinon.stub(WalletModel, 'increment')
      req = { body: { UserId: 1, paymentId: 4711, balance: 50 } }

      await addWalletBalance()(req, res, next)

      expect(increment).to.have.not.been.calledWith(sinon.match.any)
      expect(res.status).to.have.been.calledWith(402)
      expect(res.json).to.have.been.calledWith({ status: 'error', message: 'Payment not accepted.' })
    })

    it('should reject payment without any card', async () => {
      const findCard = sinon.stub(CardModel, 'findOne')
      req = { body: { UserId: 1, balance: 50 } }

      await addWalletBalance()(req, res, next)

      expect(findCard).to.have.not.been.calledWith(sinon.match.any)
      expect(res.status).to.have.been.calledWith(402)
    })

    it('should respond with 404 when wallet cannot be updated', async () => {
      sinon.stub(CardModel, 'findOne').resolves({ id: 3 } as any)
      sinon.stub(WalletModel, 'increment').rejects(new Error('DB down'))
      req = { body: { UserId: 1, paymentId: 3, balance: 50 } }

      await addWalletBalance()(req, res, next)

      expect(res.status).to.have.been.calledWith(404)
      expect(res.json).to.have.been.calledWith({ status: 'error' })
    })
  })
})
