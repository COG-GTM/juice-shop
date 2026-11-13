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
import { BasketModel } from '../../models/basket'
import { ProductModel } from '../../models/product'
import { QuantityModel } from '../../models/quantity'
import { WalletModel } from '../../models/wallet'
import * as utils from '../../lib/utils'
// @ts-expect-error FIXME no typescript definitions for z85 :(
import z85 from 'z85'

let app: Express
let authHeader: { Authorization: string, 'content-type': string }

const validCoupon = security.generateCoupon(15)
const outdatedCoupon = security.generateCoupon(20, new Date(2001, 0, 1))
const forgedCoupon = security.generateCoupon(99)
const overHundredCoupon = z85.encode(utils.toMMMYY(new Date()) + '-999999')

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

async function ownOrderDetails () {
  const cardsRes = await request(app).get('/api/Cards').set(authHeader)
  const addressesRes = await request(app).get('/api/Addresss').set(authHeader)
  return { paymentId: cardsRes.body.data[0].id, addressId: addressesRes.body.data[0].id }
}

async function walletBalance () {
  const res = await request(app).get('/rest/wallet/balance').set(authHeader)
  return res.body.data
}

void describe('/rest/basket/:id/checkout', () => {
  void it('POST placing an order for a basket is not allowed via public API', async () => {
    const res = await request(app).post('/rest/basket/1/checkout')
    assert.equal(res.status, 401)
  })

  void it('POST placing an order for an existing basket returns orderId', async () => {
    const res = await request(app).post('/rest/basket/1/checkout').set(authHeader).send({ orderDetails: await ownOrderDetails() })
    assert.equal(res.status, 200)
    assert.ok(res.body.orderConfirmation !== undefined)
  })

  void it('POST placing an order for a non-existing basket fails', async () => {
    const res = await request(app).post('/rest/basket/42/checkout').set(authHeader).send({ orderDetails: await ownOrderDetails() })
    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: Basket with id=42 does not exist.'))
  })

  void it('POST adding a negative quantity to reach a negative order total is rejected', async () => {
    const itemRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 10, quantity: -100 })
    assert.equal(itemRes.status, 400)
    assert.equal(itemRes.body.error, 'Quantity must be a positive whole number.')
  })

  void it('POST placing a wallet order for a basket containing a stored negative quantity is rejected', async () => {
    const item = await BasketItemModel.create({ BasketId: 2, ProductId: 6, quantity: -1000 }, { validate: false })
    const walletBefore = await WalletModel.findOne({ where: { UserId: 2 } })
    const stockBefore = await QuantityModel.findOne({ where: { ProductId: 6 } })
    try {
      const res = await request(app)
        .post('/rest/basket/2/checkout')
        .set(authHeader)
        .send({ UserId: 2, orderDetails: { paymentId: 'wallet' } })
      assert.equal(res.status, 400)
      assert.equal(res.body.error, 'Quantity must be a positive whole number.')

      const walletAfter = await WalletModel.findOne({ where: { UserId: 2 } })
      const stockAfter = await QuantityModel.findOne({ where: { ProductId: 6 } })
      assert.equal(walletAfter?.balance, walletBefore?.balance)
      assert.equal(stockAfter?.quantity, stockBefore?.quantity)
    } finally {
      await item.destroy()
    }
  })

  void it('POST placing an order for a basket with 99% discount is possible', async () => {
    const couponRes = await request(app)
      .put('/rest/basket/2/coupon/' + encodeURIComponent(forgedCoupon))
      .set(authHeader)
    assert.equal(couponRes.status, 200)
    assert.ok(couponRes.headers['content-type']?.includes('application/json'))
    assert.equal(couponRes.body.discount, 99)

    const res = await request(app).post('/rest/basket/2/checkout').set(authHeader).send({ orderDetails: await ownOrderDetails() })
    assert.equal(res.status, 200)
    assert.ok(res.body.orderConfirmation !== undefined)
  })

  void it('POST placing a wallet order with a coupon discount above 100% does not credit the wallet', async () => {
    const couponRes = await request(app)
      .put('/rest/basket/2/coupon/' + encodeURIComponent(overHundredCoupon))
      .set(authHeader)
    assert.equal(couponRes.status, 200)
    assert.equal(couponRes.body.discount, 100)

    const item = await BasketItemModel.create({ BasketId: 2, ProductId: 1, quantity: 1 })
    const walletBefore = await WalletModel.findOne({ where: { UserId: 2 } })
    try {
      const res = await request(app)
        .post('/rest/basket/2/checkout')
        .set(authHeader)
        .send({ UserId: 2, orderDetails: { paymentId: 'wallet' } })
      assert.equal(res.status, 200)

      const walletAfter = await WalletModel.findOne({ where: { UserId: 2 } })
      assert.equal(walletAfter?.balance, walletBefore?.balance)
    } finally {
      await item.destroy()
    }
  })
  void it('POST placing a fully discounted wallet order is not rejected because of rounding', async () => {
    const couponRes = await request(app)
      .put('/rest/basket/2/coupon/' + encodeURIComponent(overHundredCoupon))
      .set(authHeader)
    assert.equal(couponRes.status, 200)

    const product = await ProductModel.create({ name: 'Rounding Juice', description: '', price: 1.15, deluxePrice: 1.15, image: 'undefined.jpg' })
    const item = await BasketItemModel.create({ BasketId: 2, ProductId: product.id, quantity: 100 })
    const walletBefore = await WalletModel.findOne({ where: { UserId: 2 } })
    try {
      const res = await request(app)
        .post('/rest/basket/2/checkout')
        .set(authHeader)
        .send({ UserId: 2, orderDetails: { paymentId: 'wallet' } })
      assert.equal(res.status, 200)

      const walletAfter = await WalletModel.findOne({ where: { UserId: 2 } })
      assert.equal(walletAfter?.balance, walletBefore?.balance)
    } finally {
      await item.destroy()
      await product.destroy({ force: true })
    }
  })

  void it('POST placing a wallet order with a negative total is rejected without touching the wallet', async () => {
    await BasketModel.update({ coupon: null }, { where: { id: 2 } })
    const product = await ProductModel.create({ name: 'Negative Juice', description: '', price: -10, deluxePrice: -10, image: 'undefined.jpg' })
    const item = await BasketItemModel.create({ BasketId: 2, ProductId: product.id, quantity: 1 })
    const walletBefore = await WalletModel.findOne({ where: { UserId: 2 } })
    try {
      const res = await request(app)
        .post('/rest/basket/2/checkout')
        .set(authHeader)
        .send({ UserId: 2, orderDetails: { paymentId: 'wallet' } })
      assert.equal(res.status, 400)
      assert.equal(res.body.error, 'Order total must not be negative.')

      const walletAfter = await WalletModel.findOne({ where: { UserId: 2 } })
      assert.equal(walletAfter?.balance, walletBefore?.balance)
    } finally {
      await item.destroy()
      await product.destroy({ force: true })
    }
  })
  void it('POST placing a discounted wallet order with a negative subtotal is rejected without touching the wallet', async () => {
    const couponRes = await request(app)
      .put('/rest/basket/2/coupon/' + encodeURIComponent(forgedCoupon))
      .set(authHeader)
    assert.equal(couponRes.status, 200)

    const product = await ProductModel.create({ name: 'Negative Juice', description: '', price: -150, deluxePrice: -150, image: 'undefined.jpg' })
    const negativeItem = await BasketItemModel.create({ BasketId: 2, ProductId: product.id, quantity: 1 })
    const paidItem = await BasketItemModel.create({ BasketId: 2, ProductId: 1, quantity: 1 })
    const walletBefore = await WalletModel.findOne({ where: { UserId: 2 } })
    const stockBefore = await QuantityModel.findOne({ where: { ProductId: 1 } })
    try {
      const res = await request(app)
        .post('/rest/basket/2/checkout')
        .set(authHeader)
        .send({ UserId: 2, orderDetails: { paymentId: 'wallet' } })
      assert.equal(res.status, 400)
      assert.equal(res.body.error, 'Order total must not be negative.')

      const walletAfter = await WalletModel.findOne({ where: { UserId: 2 } })
      assert.equal(walletAfter?.balance, walletBefore?.balance)
      const stockAfter = await QuantityModel.findOne({ where: { ProductId: 1 } })
      assert.equal(stockAfter?.quantity, stockBefore?.quantity)
    } finally {
      await negativeItem.destroy()
      await paidItem.destroy()
      await product.destroy({ force: true })
      await BasketModel.update({ coupon: null }, { where: { id: 2 } })
    }
  })

  void it('POST placing an order without payment details is rejected and credits no bonus points', async () => {
    const balanceBefore = await walletBalance()
    const res = await request(app).post('/rest/basket/1/checkout').set(authHeader)
    assert.equal(res.status, 402)
    assert.equal(res.body.error.message, 'Payment not accepted.')
    assert.equal(await walletBalance(), balanceBefore)
  })

  void it('POST placing an order with a bogus payment id is rejected and credits no bonus points', async () => {
    const { addressId } = await ownOrderDetails()
    const balanceBefore = await walletBalance()
    for (const paymentId of ['bogus', 99999, '1 OR 1=1', { $ne: null }]) {
      const res = await request(app).post('/rest/basket/1/checkout').set(authHeader).send({ orderDetails: { paymentId, addressId } })
      assert.equal(res.status, 402)
    }
    assert.equal(await walletBalance(), balanceBefore)
  })

  void it('POST placing an order with another user\'s card is rejected', async () => {
    const { addressId } = await ownOrderDetails()
    const { token } = await login(app, { email: 'admin@juice-sh.op', password: 'admin123' })
    const adminCards = await request(app).get('/api/Cards').set({ Authorization: 'Bearer ' + token })
    const balanceBefore = await walletBalance()
    const res = await request(app).post('/rest/basket/1/checkout').set(authHeader).send({ orderDetails: { paymentId: adminCards.body.data[0].id, addressId } })
    assert.equal(res.status, 402)
    assert.equal(await walletBalance(), balanceBefore)
  })

  void it('POST placing a card order for a basket containing a stored negative quantity is rejected', async () => {
    const item = await BasketItemModel.create({ BasketId: 2, ProductId: 6, quantity: -1 }, { validate: false })
    const balanceBefore = await walletBalance()
    const stockBefore = await QuantityModel.findOne({ where: { ProductId: 6 } })
    try {
      const res = await request(app).post('/rest/basket/2/checkout').set(authHeader).send({ orderDetails: await ownOrderDetails() })
      assert.equal(res.status, 400)
      assert.equal(res.body.error, 'Quantity must be a positive whole number.')
      assert.equal(await walletBalance(), balanceBefore)
      const stockAfter = await QuantityModel.findOne({ where: { ProductId: 6 } })
      assert.equal(stockAfter?.quantity, stockBefore?.quantity)
    } finally {
      await item.destroy()
    }
  })

  void it('POST placing a wallet order with insufficient balance leaves stock and wallet untouched', async () => {
    const item = await BasketItemModel.create({ BasketId: 2, ProductId: 1, quantity: 5 })
    const wallet = await WalletModel.findOne({ where: { UserId: 2 } })
    const originalBalance = wallet?.balance ?? 0
    await WalletModel.update({ balance: 0 }, { where: { UserId: 2 } })
    const stockBefore = await QuantityModel.findOne({ where: { ProductId: 1 } })
    try {
      const res = await request(app)
        .post('/rest/basket/2/checkout')
        .set(authHeader)
        .send({ orderDetails: { paymentId: 'wallet' } })
      assert.equal(res.status, 500)
      assert.ok(res.text.includes('Insufficient wallet balance.'))
      assert.equal(await walletBalance(), 0)
      const stockAfter = await QuantityModel.findOne({ where: { ProductId: 1 } })
      assert.equal(stockAfter?.quantity, stockBefore?.quantity)
    } finally {
      await item.destroy()
      await WalletModel.update({ balance: originalBalance }, { where: { UserId: 2 } })
    }
  })

  void it('POST placing an order with another user\'s address is rejected', async () => {
    const { paymentId } = await ownOrderDetails()
    const { token } = await login(app, { email: 'admin@juice-sh.op', password: 'admin123' })
    const adminAddresses = await request(app).get('/api/Addresss').set({ Authorization: 'Bearer ' + token })
    const res = await request(app).post('/rest/basket/1/checkout').set(authHeader).send({ orderDetails: { paymentId, addressId: adminAddresses.body.data[0].id } })
    assert.equal(res.status, 400)
    assert.equal(res.body.error.message, 'Invalid address.')
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
