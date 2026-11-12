/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import * as security from '../../lib/insecurity'
import { QuantityModel } from '../../models/quantity'
import { WalletModel } from '../../models/wallet'
import * as db from '../../data/mongodb'

let app: Express
let authHeader: { Authorization: string, 'content-type': string }

const validCoupon = security.generateCoupon(15)
const outdatedCoupon = security.generateCoupon(20, new Date(2001, 0, 1))
const forgedCoupon = security.generateCoupon(99)

before(
  async () => {
    const result = await createTestApp()
    app = result.app

    const { token } = await login(app, {
      email: 'jim@juice-sh.op',
      password: 'ncc-1701'
    })
    authHeader = {
      Authorization: 'Bearer ' + token,
      'content-type': 'application/json'
    }
  },
  { timeout: 60000 }
)

void describe('/rest/basket/:id', () => {
  void it('GET existing basket by id is not allowed via public API', async () => {
    const res = await request(app).get('/rest/basket/1')
    assert.equal(res.status, 401)
  })

  void it('GET empty basket when requesting non-existing basket id', async () => {
    const res = await request(app).get('/rest/basket/4711').set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.ok(res.body.data === null || (typeof res.body.data === 'object' && Object.keys(res.body.data).length === 0))
  })

  void it('GET existing basket with contained products by id', async () => {
    const res = await request(app).get('/rest/basket/1').set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.id, 1)
    assert.equal(res.body.data.Products.length, 3)
  })

  void it.skip('GET basket should accept forged JWTs', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')
    const payload = Buffer.from(JSON.stringify({ data: { email: 'jim@juice-sh.op' }, iat: 1508639612, exp: 9999999999 })).toString('base64url')
    const unsignedToken = `${header}.${payload}.`
    const res = await request(app)
      .get('/rest/basket/1')
      .set({ Authorization: 'Bearer ' + unsignedToken, 'content-type': 'application/json' })
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
  })
})

void describe('/api/Baskets', () => {
  void it('POST new basket is not part of API', async () => {
    const res = await request(app)
      .post('/api/Baskets')
      .set(authHeader)
      .send({ UserId: 1 })
    assert.equal(res.status, 500)
  })

  void it('GET all baskets is not part of API', async () => {
    const res = await request(app).get('/api/Baskets').set(authHeader)
    assert.equal(res.status, 500)
  })
})

void describe('/api/Baskets/:id', () => {
  void it('GET existing basket is not part of API', async () => {
    const res = await request(app).get('/api/Baskets/1').set(authHeader)
    assert.equal(res.status, 500)
  })

  void it('PUT update existing basket is not part of API', async () => {
    const res = await request(app)
      .put('/api/Baskets/1')
      .set(authHeader)
      .send({ UserId: 2 })
    assert.equal(res.status, 500)
  })

  void it('DELETE existing basket is not part of API', async () => {
    const res = await request(app).delete('/api/Baskets/1').set(authHeader)
    assert.equal(res.status, 500)
  })
})

void describe('/rest/basket/:id', () => {
  void it('GET existing basket of another user', async () => {
    const { token } = await login(app, {
      email: 'bjoern.kimminich@gmail.com',
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })
    const res = await request(app)
      .get('/rest/basket/2')
      .set({ Authorization: 'Bearer ' + token })
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.id, 2)
  })
})

void describe('/rest/basket/:id/checkout', () => {
  void it('POST placing an order for a basket is not allowed via public API', async () => {
    const res = await request(app).post('/rest/basket/1/checkout')
    assert.equal(res.status, 401)
  })

  void it('POST placing an order for an existing basket returns orderId', async () => {
    const res = await request(app).post('/rest/basket/1/checkout').set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.body.orderConfirmation !== undefined)
  })

  void it('POST placing an order for a non-existing basket fails', async () => {
    const res = await request(app).post('/rest/basket/42/checkout').set(authHeader)
    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: Basket with id=42 does not exist.'))
  })

  void it('POST placing an order for a basket with a negative total cost is possible', async () => {
    const itemRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 10, quantity: -100 })
    assert.equal(itemRes.status, 200)

    const res = await request(app).post('/rest/basket/3/checkout').set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.body.orderConfirmation !== undefined)
  })

  void it('POST placing concurrent wallet orders cannot overspend the wallet', async (t) => {
    const { token } = await login(app, { email: 'uvogin@juice-sh.op', password: 'muda-muda > ora-ora' })
    const uvoginHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
    const balanceBefore = (await request(app).get('/rest/wallet/balance').set(uvoginHeader)).body.data
    const { token: adminToken } = await login(app, { email: 'admin@juice-sh.op', password: 'admin123' })
    const stockOf = async () => {
      const res = await request(app).get('/api/Quantitys').set({ Authorization: 'Bearer ' + adminToken })
      return Object.fromEntries(res.body.data.map((row: { ProductId: number, quantity: number }) => [row.ProductId, row.quantity]))
    }
    const stockBefore = await stockOf()
    const orderTotal = 5 * 8.99 + 2 * 4.99
    const bonusPoints = 5
    assert.ok(orderTotal <= balanceBefore && 2 * orderTotal > balanceBefore)

    const checkouts = 3
    let walletAccesses = 0
    let releaseBarrier: () => void = () => {}
    const barrier = new Promise<void>(resolve => { releaseBarrier = resolve })
    const awaitAllCheckouts = async () => {
      if (++walletAccesses === checkouts) releaseBarrier()
      await barrier
    }
    const findOne = WalletModel.findOne.bind(WalletModel)
    const update = WalletModel.update.bind(WalletModel)
    const findOneMock = t.mock.method(WalletModel, 'findOne', async (...args: Parameters<typeof WalletModel.findOne>) => {
      await awaitAllCheckouts()
      return await findOne(...args)
    })
    const updateMock = t.mock.method(WalletModel, 'update', async (...args: Parameters<typeof WalletModel.update>) => {
      await awaitAllCheckouts()
      return await update(...args)
    })
    const barrierTimeout = setTimeout(releaseBarrier, 5000)
    const responses = await Promise.all(Array.from({ length: checkouts }, async () => await request(app)
      .post('/rest/basket/5/checkout')
      .set(uvoginHeader)
      .send({ orderDetails: { paymentId: 'wallet' } })))
    clearTimeout(barrierTimeout)
    findOneMock.mock.restore()
    updateMock.mock.restore()
    assert.equal(walletAccesses, checkouts)
    assert.deepEqual(responses.map(res => res.status).sort(), [200, 500, 500])
    assert.equal(responses.filter(res => res.text.includes('Error: Insufficient wallet balance.')).length, 2)

    const balanceAfter = (await request(app).get('/rest/wallet/balance').set(uvoginHeader)).body.data
    assert.ok(Math.abs(balanceAfter - (balanceBefore - orderTotal + bonusPoints)) < 0.001)

    const stockAfter = await stockOf()
    assert.equal(stockAfter[3], stockBefore[3] - 5)
    assert.equal(stockAfter[4], stockBefore[4] - 2)
  })

  void it('POST placing an order for a basket with 99% discount is possible', async () => {
    const couponRes = await request(app)
      .put('/rest/basket/2/coupon/' + encodeURIComponent(forgedCoupon))
      .set(authHeader)
    assert.equal(couponRes.status, 200)
    assert.ok(couponRes.headers['content-type']?.includes('application/json'))
    assert.equal(couponRes.body.discount, 99)

    const res = await request(app).post('/rest/basket/2/checkout').set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.body.orderConfirmation !== undefined)
  })
})

void describe('/rest/basket/:id/coupon/:coupon', () => {
  void it('PUT apply valid coupon to existing basket', async () => {
    const res = await request(app)
      .put('/rest/basket/1/coupon/' + encodeURIComponent(validCoupon))
      .set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.discount, 15)
  })

  void it('PUT apply invalid coupon is not accepted', async () => {
    const res = await request(app)
      .put('/rest/basket/1/coupon/xxxxxxxxxx')
      .set(authHeader)
    assert.equal(res.status, 404)
  })

  void it('PUT apply outdated coupon is not accepted', async () => {
    const res = await request(app)
      .put('/rest/basket/1/coupon/' + encodeURIComponent(outdatedCoupon))
      .set(authHeader)
    assert.equal(res.status, 404)
  })

  void it('PUT apply valid coupon to non-existing basket throws error', async () => {
    const res = await request(app)
      .put('/rest/basket/4711/coupon/' + encodeURIComponent(validCoupon))
      .set(authHeader)
    assert.equal(res.status, 500)
  })
})

void describe('/rest/basket/:id/checkout rollback', { concurrency: false }, () => {
  let adminHeader: { Authorization: string, 'content-type': string }

  before(async () => {
    const { token } = await login(app, { email: 'admin@juice-sh.op', password: 'admin123' })
    adminHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
    const [card] = (await request(app).get('/api/Cards').set(adminHeader)).body.data
    const topUp = await request(app).put('/rest/wallet/balance').set(adminHeader).send({ paymentId: card.id, balance: 1000 })
    assert.equal(topUp.status, 200)
    for (const ProductId of [1, 2]) {
      const item = await request(app).post('/api/BasketItems').set(adminHeader).send({ BasketId: 1, ProductId, quantity: 1 })
      assert.equal(item.status, 200)
    }
  })

  const checkoutState = async () => {
    const balance = (await request(app).get('/rest/wallet/balance').set(adminHeader)).body.data
    const quantities = (await request(app).get('/api/Quantitys').set(adminHeader)).body.data
    const stock = Object.fromEntries(quantities.map((row: { ProductId: number, quantity: number }) => [row.ProductId, row.quantity]))
    const basketItems = (await request(app).get('/rest/basket/1').set(adminHeader)).body.data.Products.length
    return { balance, stock: [stock[1], stock[2]], basketItems }
  }

  const walletCheckout = async () => await request(app)
    .post('/rest/basket/1/checkout')
    .set(adminHeader)
    .send({ orderDetails: { paymentId: 'wallet' } })

  void it('POST checkout restores wallet and stock when a stock reduction fails', async (t) => {
    const before = await checkoutState()

    const decrement = QuantityModel.decrement.bind(QuantityModel)
    const decrementMock = t.mock.method(QuantityModel, 'decrement', async (...args: Parameters<typeof QuantityModel.decrement>) => {
      if (decrementMock.mock.callCount() === 1) throw new Error('stock update failed')
      return await decrement(...args)
    })
    const res = await walletCheckout()
    decrementMock.mock.restore()

    assert.equal(decrementMock.mock.callCount(), 2)
    assert.equal(res.status, 500)
    assert.ok(res.text.includes('stock update failed'))
    assert.deepEqual(await checkoutState(), before)
  })

  void it('POST checkout restores wallet and stock when storing the order fails', async (t) => {
    const before = await checkoutState()

    const insertMock = t.mock.method(db.ordersCollection, 'insert', async () => { throw new Error('order insert failed') })
    const res = await walletCheckout()
    insertMock.mock.restore()

    assert.equal(insertMock.mock.callCount(), 1)
    assert.equal(res.status, 500)
    assert.ok(res.text.includes('order insert failed'))
    assert.deepEqual(await checkoutState(), before)
  })
})
