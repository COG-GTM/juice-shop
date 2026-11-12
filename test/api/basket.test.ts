/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import * as security from '../../lib/insecurity'
import { BasketItemModel } from '../../models/basketitem'
import { QuantityModel } from '../../models/quantity'
import { WalletModel } from '../../models/wallet'

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

  void it('POST adding a negative quantity to reach a negative order total is rejected', async () => {
    const itemRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: 2, ProductId: 10, quantity: -100 })
    assert.equal(itemRes.status, 400)
    assert.equal(itemRes.body.error, 'Quantity must be a positive whole number.')
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

  void it('POST placing an order for more items than are in stock returns 400 and restores stock', async () => {
    const item = await BasketItemModel.create({ BasketId: 2, ProductId: 6, quantity: 2 })
    const stockBefore = await QuantityModel.findOne({ where: { ProductId: 6 } })
    const otherStockBefore = await QuantityModel.findOne({ where: { ProductId: 4 } })
    const walletBefore = await WalletModel.findOne({ where: { UserId: 2 } })
    await QuantityModel.update({ quantity: 1 }, { where: { ProductId: 6 } })
    try {
      const res = await request(app)
        .post('/rest/basket/2/checkout')
        .set(authHeader)
        .send({ UserId: 2, orderDetails: { paymentId: 'wallet' } })
      assert.equal(res.status, 400)
      assert.equal(res.body.error, 'We are out of stock! Sorry for the inconvenience.')

      const stockAfter = await QuantityModel.findOne({ where: { ProductId: 6 } })
      const otherStockAfter = await QuantityModel.findOne({ where: { ProductId: 4 } })
      const walletAfter = await WalletModel.findOne({ where: { UserId: 2 } })
      assert.equal(stockAfter?.quantity, 1)
      assert.equal(otherStockAfter?.quantity, otherStockBefore?.quantity)
      assert.equal(walletAfter?.balance, walletBefore?.balance)
    } finally {
      await QuantityModel.update({ quantity: stockBefore?.quantity }, { where: { ProductId: 6 } })
      await item.destroy()
    }
  })

  void it('POST placing an underfunded wallet order leaves stock unchanged and no order PDF behind', async () => {
    const item = await BasketItemModel.create({ BasketId: 2, ProductId: 6, quantity: 100000 })
    const originalStock = await QuantityModel.findOne({ where: { ProductId: 6 } })
    await QuantityModel.update({ quantity: 100000 }, { where: { ProductId: 6 } })
    const walletBefore = await WalletModel.findOne({ where: { UserId: 2 } })
    const stockBefore = await QuantityModel.findAll({ order: [['ProductId', 'ASC']] })
    const orderPdfs = () => fs.readdirSync('ftp').filter(file => file.startsWith('order_') && file.endsWith('.pdf')).sort()
    const pdfsBefore = orderPdfs()
    try {
      const res = await request(app)
        .post('/rest/basket/2/checkout')
        .set(authHeader)
        .send({ UserId: 2, orderDetails: { paymentId: 'wallet' } })
      assert.equal(res.status, 500)
      assert.ok(res.text.includes('Error: Insufficient wallet balance.'))

      const walletAfter = await WalletModel.findOne({ where: { UserId: 2 } })
      const stockAfter = await QuantityModel.findAll({ order: [['ProductId', 'ASC']] })
      assert.equal(walletAfter?.balance, walletBefore?.balance)
      assert.deepEqual(stockAfter.map(({ ProductId, quantity }) => ({ ProductId, quantity })), stockBefore.map(({ ProductId, quantity }) => ({ ProductId, quantity })))
      await new Promise(resolve => setTimeout(resolve, 500))
      assert.deepEqual(orderPdfs(), pdfsBefore)
    } finally {
      await QuantityModel.update({ quantity: originalStock?.quantity }, { where: { ProductId: 6 } })
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
