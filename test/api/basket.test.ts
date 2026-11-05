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
import { BasketItemModel } from '../../models/basketitem'
import { CardModel } from '../../models/card'

let app: Express
let authHeader: { Authorization: string, 'content-type': string }
let ownBasketId: number

const validCoupon = security.generateCoupon(15)
const outdatedCoupon = security.generateCoupon(20, new Date(2001, 0, 1))
const forgedCoupon = security.generateCoupon(99)

before(
  async () => {
    const result = await createTestApp()
    app = result.app

    const { token, bid } = await login(app, {
      email: 'jim@juice-sh.op',
      password: 'ncc-1701'
    })
    ownBasketId = bid
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

async function usableCardId (header: { Authorization: string, 'content-type': string }) {
  const cards = (await request(app).get('/api/Cards').set(header)).body.data
  if (cards.length > 0) return cards[0].id
  const res = await request(app).post('/api/Cards').set(header).send({ fullName: 'Test Buyer', cardNum: 4111111111111111, expMonth: 12, expYear: 2090 })
  assert.equal(res.status, 201)
  return res.body.data.id
}

void describe('/rest/basket/:id/checkout', () => {
  void it('POST placing an order for a basket is not allowed via public API', async () => {
    const res = await request(app).post('/rest/basket/1/checkout')
    assert.equal(res.status, 401)
  })

  void it('POST placing an order without a payment method is rejected and leaves the basket untouched', async () => {
    const itemsBefore = await BasketItemModel.count({ where: { BasketId: 2 } })
    assert.ok(itemsBefore > 0)

    for (const orderDetails of [undefined, { paymentId: 'card' }, { paymentId: 4711 }, { paymentId: { $gt: 0 } }]) {
      const res = await request(app).post('/rest/basket/2/checkout').set(authHeader).send({ orderDetails })
      assert.equal(res.status, 400)
      assert.equal(res.body.error, 'Invalid payment method.')
    }
    assert.equal(await BasketItemModel.count({ where: { BasketId: 2 } }), itemsBefore)
  })

  void it('POST placing an order paid with another user\'s card is rejected', async () => {
    const { token } = await login(app, { email: 'bender@juice-sh.op', password: 'OhG0dPlease1nsertLiquor!' })
    const benderCardId = await usableCardId({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
    const walletBefore = (await request(app).get('/rest/wallet/balance').set(authHeader)).body.data

    const res = await request(app).post('/rest/basket/2/checkout').set(authHeader).send({ orderDetails: { paymentId: benderCardId } })
    assert.equal(res.status, 400)
    assert.equal((await request(app).get('/rest/wallet/balance').set(authHeader)).body.data, walletBefore)
  })

  void it('POST placing an order paid with an expired own card is rejected', async () => {
    const cardRes = await request(app).post('/api/Cards').set(authHeader).send({ fullName: 'Jim', cardNum: 4111111111111111, expMonth: 1, expYear: 2081 })
    assert.equal(cardRes.status, 201)
    await CardModel.update({ expYear: 2001 }, { where: { id: cardRes.body.data.id }, validate: false })

    const res = await request(app).post('/rest/basket/2/checkout').set(authHeader).send({ orderDetails: { paymentId: cardRes.body.data.id } })
    assert.equal(res.status, 400)
  })

  void it('POST placing an order for the own basket paid with an own card returns orderId', async () => {
    const res = await request(app).post('/rest/basket/2/checkout').set(authHeader).send({ orderDetails: { paymentId: await usableCardId(authHeader) } })
    assert.equal(res.status, 200)
    assert.ok(res.body.orderConfirmation !== undefined)
  })

  void it('POST placing an order for another user\'s basket is forbidden and leaves it untouched', async () => {
    const itemsBefore = await BasketItemModel.count({ where: { BasketId: 1 } })
    assert.ok(itemsBefore > 0)

    const res = await request(app).post('/rest/basket/1/checkout').set(authHeader)
    assert.equal(res.status, 403)
    assert.equal(res.body.orderConfirmation, undefined)
    assert.equal(await BasketItemModel.count({ where: { BasketId: 1 } }), itemsBefore)
  })

  void it('POST placing an order for a non-existing basket is forbidden', async () => {
    const res = await request(app).post('/rest/basket/42/checkout').set(authHeader)
    assert.equal(res.status, 403)
  })

  void it('POST placing an order for a basket with a negative total cost is possible', async () => {
    const itemRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 10, quantity: -100 })
    assert.equal(itemRes.status, 200)

    const res = await request(app).post('/rest/basket/2/checkout').set(authHeader).send({ orderDetails: { paymentId: await usableCardId(authHeader) } })
    assert.equal(res.status, 200)
    assert.ok(res.body.orderConfirmation !== undefined)
  })

  void it('POST placing concurrent wallet orders cannot overspend the wallet', async () => {
    const { token } = await login(app, { email: 'uvogin@juice-sh.op', password: 'muda-muda > ora-ora' })
    const uvoginHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
    const balanceBefore = (await request(app).get('/rest/wallet/balance').set(uvoginHeader)).body.data
    const orderTotal = 5 * 8.99 + 2 * 4.99
    const bonusPoints = 5
    assert.ok(orderTotal <= balanceBefore && 2 * orderTotal > balanceBefore)

    const responses = await Promise.all([1, 2, 3].map(async () => await request(app)
      .post('/rest/basket/5/checkout')
      .set(uvoginHeader)
      .send({ orderDetails: { paymentId: 'wallet' } })))
    assert.deepEqual(responses.map(res => res.status).sort(), [200, 500, 500])
    assert.equal(responses.filter(res => res.text.includes('Error: Insufficient wallet balance.')).length, 2)

    const balanceAfter = (await request(app).get('/rest/wallet/balance').set(uvoginHeader)).body.data
    assert.ok(Math.abs(balanceAfter - (balanceBefore - orderTotal + bonusPoints)) < 0.001)
  })

  void it('POST placing an order for a basket with 99% discount is possible', async () => {
    const couponRes = await request(app)
      .put(`/rest/basket/${ownBasketId}/coupon/` + encodeURIComponent(forgedCoupon))
      .set(authHeader)
    assert.equal(couponRes.status, 200)
    assert.ok(couponRes.headers['content-type']?.includes('application/json'))
    assert.equal(couponRes.body.discount, 99)

    const res = await request(app).post(`/rest/basket/${ownBasketId}/checkout`).set(authHeader).send({ orderDetails: { paymentId: await usableCardId(authHeader) } })
    assert.equal(res.status, 200)
    assert.ok(res.body.orderConfirmation !== undefined)
  })
})

void describe('/rest/basket/:id/coupon/:coupon', () => {
  void it('PUT apply valid coupon to own basket', async () => {
    const res = await request(app)
      .put(`/rest/basket/${ownBasketId}/coupon/` + encodeURIComponent(validCoupon))
      .set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.discount, 15)
  })

  void it('PUT apply invalid coupon is not accepted', async () => {
    const res = await request(app)
      .put(`/rest/basket/${ownBasketId}/coupon/xxxxxxxxxx`)
      .set(authHeader)
    assert.equal(res.status, 404)
  })

  void it('PUT apply outdated coupon is not accepted', async () => {
    const res = await request(app)
      .put(`/rest/basket/${ownBasketId}/coupon/` + encodeURIComponent(outdatedCoupon))
      .set(authHeader)
    assert.equal(res.status, 404)
  })

  void it('PUT apply valid coupon to another user\'s basket is forbidden', async () => {
    const res = await request(app)
      .put('/rest/basket/1/coupon/' + encodeURIComponent(validCoupon))
      .set(authHeader)
    assert.equal(res.status, 403)
  })

  void it('PUT invalid coupon to another user\'s basket is forbidden and leaves its coupon untouched', async () => {
    const { token: adminToken } = await login(app, {
      email: 'admin@juice-sh.op',
      password: 'admin123'
    })
    const adminHeader = { Authorization: 'Bearer ' + adminToken, 'content-type': 'application/json' }
    const applied = await request(app)
      .put('/rest/basket/1/coupon/' + encodeURIComponent(validCoupon))
      .set(adminHeader)
    assert.equal(applied.status, 200)

    const res = await request(app)
      .put('/rest/basket/1/coupon/xxxxxxxxxx')
      .set(authHeader)
    assert.equal(res.status, 403)

    const basket = await request(app)
      .get('/rest/basket/1')
      .set(adminHeader)
    assert.equal(basket.body.data.coupon, validCoupon)
  })

  void it('PUT apply valid coupon to non-existing basket is forbidden', async () => {
    const res = await request(app)
      .put('/rest/basket/4711/coupon/' + encodeURIComponent(validCoupon))
      .set(authHeader)
    assert.equal(res.status, 403)
  })
})

void describe('/rest/basket/:id/checkout with campaign couponData', () => {
  const expiredCampaignValidOn = new Date('Mar 08, 2019 00:00:00 GMT+0100').getTime()
  const expiredCampaignCouponData = Buffer.from(`WMNSDY2019-${expiredCampaignValidOn}`).toString('base64')

  async function checkoutWithCampaignCoupon (productId: number, couponData: string) {
    const { token, bid } = await login(app, {
      email: 'accountant@juice-sh.op',
      password: 'i am an awesome accountant'
    })
    const accountantHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const itemRes = await request(app)
      .post('/api/BasketItems')
      .set(accountantHeader)
      .send({ BasketId: bid, ProductId: productId, quantity: 1 })
    assert.equal(itemRes.status, 200)

    const res = await request(app)
      .post(`/rest/basket/${bid}/checkout`)
      .set(accountantHeader)
      .send({ couponData, orderDetails: { paymentId: await usableCardId(accountantHeader) } })
    assert.equal(res.status, 200)

    const historyRes = await request(app).get('/rest/order-history').set(accountantHeader)
    return historyRes.body.data.find((order: { orderId: string }) => order.orderId === res.body.orderConfirmation)
  }

  void it('POST expired campaign coupon with its original campaign date grants no discount', async () => {
    const order = await checkoutWithCampaignCoupon(1, expiredCampaignCouponData)
    assert.equal(order.promotionalAmount, '0')
  })

  void it('POST campaign coupon is honored while the server clock is within the campaign day', async (t) => {
    t.mock.method(Date, 'now', () => expiredCampaignValidOn + 60 * 60 * 1000)
    const order = await checkoutWithCampaignCoupon(2, Buffer.from(`WMNSDY2019-${Date.now() + 7 * 24 * 60 * 60 * 1000}`).toString('base64'))
    assert.notEqual(order.promotionalAmount, '0')
  })
})
