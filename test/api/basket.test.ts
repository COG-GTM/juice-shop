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

interface AuthHeader { Authorization: string, 'content-type': string }

let app: Express
let authHeader: AuthHeader
let jimUserId: number

const validCoupon = security.generateCoupon(15)
const outdatedCoupon = security.generateCoupon(20, new Date(2001, 0, 1))
const forgedCoupon = security.generateCoupon(99)
const womensDay2019 = new Date('Mar 08, 2019 00:00:00 GMT+0100').getTime()

const round = (amount: number) => Math.round(amount * 100) / 100

async function product (id: number) {
  const res = await request(app).get(`/api/Products/${id}`).set(authHeader)
  assert.equal(res.status, 200)
  return res.body.data as { price: number, deluxePrice: number }
}

async function addToBasket (basketId: number, productId: number, quantity: number, header: AuthHeader) {
  const res = await request(app)
    .post('/api/BasketItems')
    .set(header)
    .send({ BasketId: basketId, ProductId: productId, quantity })
  assert.equal(res.status, 200)
  return res.body.data.id as number
}

async function userId (header: AuthHeader) {
  const res = await request(app).get('/rest/user/whoami').set(header)
  assert.equal(res.status, 200)
  return res.body.user.id as number
}

async function stock (productId: number) {
  const res = await request(app).get('/api/Quantitys').set(authHeader)
  assert.equal(res.status, 200)
  const quantityRow = res.body.data.find((row: { ProductId: number }) => row.ProductId === productId)
  return quantityRow.quantity as number
}

async function walletBalance (header: AuthHeader) {
  const res = await request(app).get('/rest/wallet/balance').set(header)
  assert.equal(res.status, 200)
  return res.body.data as number
}

async function trackOrder (orderId: string) {
  const res = await request(app).get(`/rest/track-order/${orderId}`).set(authHeader)
  assert.equal(res.status, 200)
  return res.body.data[0]
}

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

    jimUserId = await userId(authHeader)
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

  void it('POST placing an order paid by wallet debits the total price and credits the bonus points', async () => {
    const { price } = await product(3)
    const quantity = 2
    await addToBasket(2, 3, quantity, authHeader)
    const balanceBefore = await walletBalance(authHeader)

    const res = await request(app)
      .post('/rest/basket/2/checkout')
      .set(authHeader)
      .send({ UserId: jimUserId, orderDetails: { paymentId: 'wallet' } })
    assert.equal(res.status, 200)

    const order = await trackOrder(res.body.orderConfirmation)
    assert.equal(round(order.totalPrice), round(price * quantity))
    assert.equal(order.bonus, Math.round(price / 10) * quantity)
    assert.equal(round(await walletBalance(authHeader)), round(balanceBefore - order.totalPrice + order.bonus))
  })

  void it('POST placing an order paid by wallet fails when the wallet balance is too low', async () => {
    const { token } = await login(app, {
      email: 'bender@juice-sh.op',
      password: 'OhG0dPlease1nsertLiquor!'
    })
    const benderHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
    const benderUserId = await userId(benderHeader)
    assert.equal(await walletBalance(benderHeader), 0)
    const basketItemId = await addToBasket(3, 1, 1, benderHeader)
    const stockBefore = await stock(1)

    const res = await request(app)
      .post('/rest/basket/3/checkout')
      .set(benderHeader)
      .send({ UserId: benderUserId, orderDetails: { paymentId: 'wallet' } })
    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: Insufficient wallet balance.'))
    assert.equal(await walletBalance(benderHeader), 0)
    assert.equal(await stock(1), stockBefore - 1, 'stock is decremented before the payment is rejected')

    await request(app).delete(`/api/BasketItems/${basketItemId}`).set(benderHeader)
  })

  void it('POST placing an order with a delivery method adds its price and eta to the order', async () => {
    const deliveryRes = await request(app).get('/api/Deliverys/1').set(authHeader)
    assert.equal(deliveryRes.status, 200)
    const deliveryMethod = deliveryRes.body.data
    const { price } = await product(1)
    await addToBasket(2, 1, 1, authHeader)

    const res = await request(app)
      .post('/rest/basket/2/checkout')
      .set(authHeader)
      .send({ orderDetails: { deliveryMethodId: deliveryMethod.id } })
    assert.equal(res.status, 200)

    const order = await trackOrder(res.body.orderConfirmation)
    assert.equal(order.deliveryPrice, deliveryMethod.price)
    assert.equal(order.eta, String(deliveryMethod.eta))
    assert.equal(round(order.totalPrice), round(price + deliveryMethod.price))
  })

  void it('POST placing an order as a deluxe member uses deluxe product and delivery prices', async () => {
    const { token } = await login(app, {
      email: 'uvogin@juice-sh.op',
      password: 'muda-muda > ora-ora'
    })
    const customerHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
    const { deluxePrice } = await product(1)
    await addToBasket(5, 1, 1, customerHeader)

    const upgradeRes = await request(app)
      .post('/rest/deluxe-membership')
      .set(customerHeader)
      .send({ UserId: await userId(customerHeader), paymentMode: 'wallet' })
    assert.equal(upgradeRes.status, 200)
    const deluxeHeader = { Authorization: 'Bearer ' + upgradeRes.body.data.token, 'content-type': 'application/json' }

    const deliveryRes = await request(app).get('/api/Deliverys/1').set(deluxeHeader)
    const deluxeDeliveryPrice = deliveryRes.body.data.price

    const res = await request(app)
      .post('/rest/basket/5/checkout')
      .set(deluxeHeader)
      .send({ orderDetails: { deliveryMethodId: 1 } })
    assert.equal(res.status, 200)

    const order = await trackOrder(res.body.orderConfirmation)
    assert.equal(order.deliveryPrice, deluxeDeliveryPrice)
    const orderedProduct = order.products.find((item: { id: number }) => item.id === 1)
    assert.equal(orderedProduct.price, deluxePrice)
    const expectedTotal = order.products.reduce((sum: number, item: { total: number }) => sum + item.total, deluxeDeliveryPrice)
    assert.equal(round(order.totalPrice), round(expectedTotal))
  })

  void it('POST placing an order with a campaign coupon applies its discount', async () => {
    const { price } = await product(1)
    await addToBasket(2, 1, 1, authHeader)

    const res = await request(app)
      .post('/rest/basket/2/checkout')
      .set(authHeader)
      .send({ couponData: Buffer.from(`WMNSDY2019-${womensDay2019}`).toString('base64') })
    assert.equal(res.status, 200)

    const order = await trackOrder(res.body.orderConfirmation)
    const discountAmount = (price * 0.75).toFixed(2)
    assert.equal(order.promotionalAmount, discountAmount)
    assert.equal(round(order.totalPrice), round(price - parseFloat(discountAmount)))
  })

  void it('POST placing an order with a campaign coupon for another date is not discounted', async () => {
    const { price } = await product(1)
    await addToBasket(2, 1, 1, authHeader)

    const res = await request(app)
      .post('/rest/basket/2/checkout')
      .set(authHeader)
      .send({ couponData: Buffer.from(`WMNSDY2019-${womensDay2019 + 1}`).toString('base64') })
    assert.equal(res.status, 200)

    const order = await trackOrder(res.body.orderConfirmation)
    assert.equal(order.promotionalAmount, '0')
    assert.equal(round(order.totalPrice), round(price))
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
