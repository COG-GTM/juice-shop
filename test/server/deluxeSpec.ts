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
import { WalletModel } from '../../models/wallet'
import { CardModel } from '../../models/card'
import * as security from '../../lib/insecurity'
import { upgradeToDeluxe, deluxeMembershipStatus } from '../../routes/deluxe'

const expect = chai.expect
chai.use(sinonChai)

describe('deluxe', () => {
  const originalChallenges = { ...challenges }

  after(() => {
    for (const key of Object.keys(challenges)) {
      delete challenges[key]
    }
    Object.assign(challenges, originalChallenges)
  })

  let req: any
  let res: any
  let next: any
  let save: any

  beforeEach(() => {
    res = { json: sinon.spy(), status: sinon.stub() }
    res.status.returns(res)
    next = sinon.spy()
    save = () => ({
      then () { }
    })
  })

  afterEach(() => {
    sinon.restore()
  })

  describe('upgradeToDeluxe', () => {
    let user: any

    beforeEach(() => {
      user = { id: 1, email: 'jim@juice-sh.op' }
      user.update = sinon.stub().callsFake(async (values: any) => ({ ...user, ...values }))
      challenges.freeDeluxeChallenge = { solved: false, save } as unknown as Challenge
    })

    it('should respond with 400 when user is not a customer', async () => {
      const findOne = sinon.stub(UserModel, 'findOne').resolves(null)
      req = { body: { UserId: 1, paymentMode: 'wallet' }, headers: {} }

      await upgradeToDeluxe()(req, res, next)

      expect(findOne).to.have.been.calledWith({ where: { id: 1, role: 'customer' } })
      expect(res.status).to.have.been.calledWith(400)
      expect(res.json).to.have.been.calledWith({ status: 'error', error: 'Something went wrong. Please try again!' })
    })

    it('should reject wallet payment with insufficient funds', async () => {
      sinon.stub(UserModel, 'findOne').resolves(user)
      sinon.stub(WalletModel, 'findOne').resolves({ balance: 48 } as any)
      const decrement = sinon.stub(WalletModel, 'decrement')
      req = { body: { UserId: 1, paymentMode: 'wallet' }, headers: {} }

      await upgradeToDeluxe()(req, res, next)

      expect(decrement).to.have.not.been.calledWith(sinon.match.any)
      expect(res.status).to.have.been.calledWith(400)
      expect(res.json).to.have.been.calledWith({ status: 'error', error: 'Insuffienct funds in Wallet' })
    })

    it('should charge 49 from wallet and upgrade user to deluxe', async () => {
      sinon.stub(UserModel, 'findOne').resolves(user)
      sinon.stub(WalletModel, 'findOne').resolves({ balance: 100 } as any)
      const decrement = sinon.stub(WalletModel, 'decrement').resolves()
      req = { body: { UserId: 1, paymentMode: 'wallet' }, headers: {} }

      await upgradeToDeluxe()(req, res, next)

      expect(decrement).to.have.been.calledWith({ balance: 49 }, { where: { UserId: 1 } })
      expect(user.update).to.have.been.calledWith({ role: 'deluxe', deluxeToken: security.deluxeToken(user.email) })
      expect(res.status).to.have.been.calledWith(200)
      expect(res.json).to.have.been.calledWith(sinon.match({ status: 'success', data: sinon.match({ confirmation: 'Congratulations! You are now a deluxe member!', token: sinon.match.string }) }))
      expect(challenges.freeDeluxeChallenge.solved).to.equal(false)
    })

    it('should register upgraded user under the new token', async () => {
      sinon.stub(UserModel, 'findOne').resolves(user)
      sinon.stub(WalletModel, 'findOne').resolves({ balance: 100 } as any)
      sinon.stub(WalletModel, 'decrement').resolves()
      req = { body: { UserId: 1, paymentMode: 'wallet' }, headers: {} }

      await upgradeToDeluxe()(req, res, next)

      const token = res.json.firstCall.args[0].data.token
      expect(security.authenticatedUsers.get(token)).to.deep.include({ status: 'success' })
      expect(security.authenticatedUsers.get(token)?.data).to.include({ role: 'deluxe' })
    })

    it('should reject payment with unknown card', async () => {
      sinon.stub(UserModel, 'findOne').resolves(user)
      sinon.stub(CardModel, 'findOne').resolves(null)
      req = { body: { UserId: 1, paymentMode: 'card', paymentId: 4711 }, headers: {} }

      await upgradeToDeluxe()(req, res, next)

      expect(user.update).to.have.not.been.calledWith(sinon.match.any)
      expect(res.status).to.have.been.calledWith(400)
      expect(res.json).to.have.been.calledWith({ status: 'error', error: 'Invalid Card' })
    })

    it('should reject payment with expired card', async () => {
      sinon.stub(UserModel, 'findOne').resolves(user)
      sinon.stub(CardModel, 'findOne').resolves({ expYear: new Date().getFullYear() - 1, expMonth: 12 } as any)
      req = { body: { UserId: 1, paymentMode: 'card', paymentId: 3 }, headers: {} }

      await upgradeToDeluxe()(req, res, next)

      expect(res.status).to.have.been.calledWith(400)
      expect(res.json).to.have.been.calledWith({ status: 'error', error: 'Invalid Card' })
    })

    it('should upgrade user when paying with valid card', async () => {
      sinon.stub(UserModel, 'findOne').resolves(user)
      sinon.stub(CardModel, 'findOne').resolves({ expYear: new Date().getFullYear() + 1, expMonth: 1 } as any)
      req = { body: { UserId: 1, paymentMode: 'card', paymentId: 3 }, headers: {} }

      await upgradeToDeluxe()(req, res, next)

      expect(res.status).to.have.been.calledWith(200)
      expect(challenges.freeDeluxeChallenge.solved).to.equal(false)
    })

    it('should solve "freeDeluxeChallenge" when upgrading without any payment mode', async () => {
      sinon.stub(UserModel, 'findOne').resolves(user)
      req = { body: { UserId: 1 }, headers: { authorization: 'Bearer ' + security.authorize({ data: { id: 1 } }) } }

      await upgradeToDeluxe()(req, res, next)

      expect(res.status).to.have.been.calledWith(200)
      expect(challenges.freeDeluxeChallenge.solved).to.equal(true)
    })

    it('should respond with 400 when user update fails', async () => {
      user.update = sinon.stub().rejects(new Error('DB down'))
      sinon.stub(UserModel, 'findOne').resolves(user)
      req = { body: { UserId: 1 }, headers: {} }

      await upgradeToDeluxe()(req, res, next)

      expect(res.status).to.have.been.calledWith(400)
      expect(res.json).to.have.been.calledWith({ status: 'error', error: 'Something went wrong. Please try again!' })
    })

    it('should respond with 400 and error details on database errors', async () => {
      sinon.stub(UserModel, 'findOne').rejects(new Error('DB down'))
      req = { body: { UserId: 1 }, headers: {} }

      await upgradeToDeluxe()(req, res, next)

      expect(res.status).to.have.been.calledWith(400)
      expect(res.json).to.have.been.calledWith({ status: 'error', error: 'Something went wrong: DB down' })
    })
  })

  describe('deluxeMembershipStatus', () => {
    const requestWithUser = (data: Record<string, unknown>) => ({ headers: { authorization: 'Bearer ' + security.authorize({ data }) } })

    it('should offer membership to customers', () => {
      deluxeMembershipStatus()(requestWithUser({ role: 'customer' }) as any, res, next)

      expect(res.status).to.have.been.calledWith(200)
      expect(res.json).to.have.been.calledWith({ status: 'success', data: { membershipCost: 49 } })
    })

    it('should tell deluxe members that they already are members', () => {
      const email = 'bjoern@owasp.org'
      deluxeMembershipStatus()(requestWithUser({ role: 'deluxe', email, deluxeToken: security.deluxeToken(email) }) as any, res, next)

      expect(res.status).to.have.been.calledWith(400)
      expect(res.json).to.have.been.calledWith({ status: 'error', error: 'You are already a deluxe member!' })
    })

    it('should not accept deluxe role with forged deluxe token', () => {
      deluxeMembershipStatus()(requestWithUser({ role: 'deluxe', email: 'bjoern@owasp.org', deluxeToken: 'forged' }) as any, res, next)

      expect(res.json).to.have.been.calledWith({ status: 'error', error: 'You are not eligible for deluxe membership!' })
    })

    it('should not offer membership to other roles', () => {
      deluxeMembershipStatus()(requestWithUser({ role: 'admin' }) as any, res, next)

      expect(res.status).to.have.been.calledWith(400)
      expect(res.json).to.have.been.calledWith({ status: 'error', error: 'You are not eligible for deluxe membership!' })
    })

    it('should not offer membership to anonymous users', () => {
      deluxeMembershipStatus()({ headers: {} } as any, res, next)

      expect(res.json).to.have.been.calledWith({ status: 'error', error: 'You are not eligible for deluxe membership!' })
    })
  })
})
