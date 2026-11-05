/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import fs from 'node:fs'
import path from 'node:path'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import { ordersCollection } from '../../data/mongodb'
import * as security from '../../lib/insecurity'
import { ORDERS_DIR } from '../../routes/order'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/order-history', () => {
  void it('GET own previous orders', async () => {
    const { token } = await login(app, {
      email: 'admin@' + config.get<string>('application.domain'),
      password: 'admin123'
    })

    const res = await request(app)
      .get('/rest/order-history')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })

    assert.equal(res.status, 200)
    assert.equal(res.body.data[0].totalPrice, 8.96)
    assert.equal(res.body.data[0].delivered, false)
    assert.equal(res.body.data[0].products[0].quantity, 3)
    assert.equal(res.body.data[0].products[0].name, 'Apple Juice (1000ml)')
    assert.equal(res.body.data[0].products[0].price, 1.99)
    assert.equal(res.body.data[0].products[0].total, 5.97)
    assert.equal(res.body.data[0].products[1].quantity, 1)
    assert.equal(res.body.data[0].products[1].name, 'Orange Juice (1000ml)')
    assert.equal(res.body.data[0].products[1].price, 2.99)
    assert.equal(res.body.data[0].products[1].total, 2.99)
    assert.equal(res.body.data[1].totalPrice, 26.97)
    assert.equal(res.body.data[1].delivered, true)
    assert.equal(res.body.data[1].products[0].quantity, 3)
    assert.equal(res.body.data[1].products[0].name, 'Eggfruit Juice (500ml)')
    assert.equal(res.body.data[1].products[0].price, 8.99)
    assert.equal(res.body.data[1].products[0].total, 26.97)
  })
})

void describe('/rest/order-history/orders', () => {
  void it('GET all orders is forbidden for customers', async () => {
    const { token } = await login(app, {
      email: 'jim@' + config.get<string>('application.domain'),
      password: 'ncc-1701'
    })

    const res = await request(app)
      .get('/rest/order-history/orders')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })

    assert.equal(res.status, 403)
  })

  void it('GET all orders is forbidden for admin', async () => {
    const { token } = await login(app, {
      email: 'admin@' + config.get<string>('application.domain'),
      password: 'admin123'
    })

    const res = await request(app)
      .get('/rest/order-history/orders')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })

    assert.equal(res.status, 403)
  })

  void it('GET all orders for accountant', async () => {
    const { token } = await login(app, {
      email: 'accountant@' + config.get<string>('application.domain'),
      password: 'i am an awesome accountant'
    })

    const res = await request(app)
      .get('/rest/order-history/orders')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })

    assert.equal(res.status, 200)
  })
})

void describe('/rest/order-history/:id/delivery-status', () => {
  void it('PUT delivery status is forbidden for admin', async () => {
    const { token } = await login(app, {
      email: 'admin@' + config.get<string>('application.domain'),
      password: 'admin123'
    })

    const res = await request(app)
      .put('/rest/order-history/1/delivery-status')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      .send({ delivered: false })

    assert.equal(res.status, 403)
  })

  void it('PUT delivery status is forbidden for customer', async () => {
    const { token } = await login(app, {
      email: 'jim@' + config.get<string>('application.domain'),
      password: 'ncc-1701'
    })

    const res = await request(app)
      .put('/rest/order-history/1/delivery-status')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      .send({ delivered: false })

    assert.equal(res.status, 403)
  })

  void it('PUT delivery status is allowed for accountant', async () => {
    const { token } = await login(app, {
      email: 'accountant@' + config.get<string>('application.domain'),
      password: 'i am an awesome accountant'
    })

    const res = await request(app)
      .put('/rest/order-history/1/delivery-status')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      .send({ delivered: false })

    assert.equal(res.status, 200)
  })
})

void describe('/rest/order-history/:id/confirmation', () => {
  async function placeOrder (email: string, password: string, basketId: number) {
    const { token } = await login(app, { email, password })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
    const res = await request(app).post(`/rest/basket/${basketId}/checkout`).set(authHeader)
    assert.equal(res.status, 200)
    return { orderId: res.body.orderConfirmation as string, authHeader }
  }

  void it('GET own order confirmation PDF', async () => {
    const { orderId, authHeader } = await placeOrder('jim@' + config.get<string>('application.domain'), 'ncc-1701', 2)

    const res = await request(app)
      .get(`/rest/order-history/${orderId}/confirmation`)
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/pdf'))
  })

  void it('GET order confirmation PDF without authentication is denied', async () => {
    const { orderId } = await placeOrder('bender@' + config.get<string>('application.domain'), 'OhG0dPlease1nsertLiquor!', 3)

    const res = await request(app).get(`/rest/order-history/${orderId}/confirmation`)

    assert.equal(res.status, 401)
  })

  void it('GET order confirmation PDF of another user is denied', async () => {
    const { orderId } = await placeOrder('jim@' + config.get<string>('application.domain'), 'ncc-1701', 2)
    const { token } = await login(app, { email: 'admin@' + config.get<string>('application.domain'), password: 'admin123' })

    const res = await request(app)
      .get(`/rest/order-history/${orderId}/confirmation`)
      .set({ Authorization: 'Bearer ' + token })

    assert.equal(res.status, 404)
  })

  void it('GET order confirmation PDF of a user with colliding masked email and hash prefix is denied', async () => {
    const email = 'jim@' + config.get<string>('application.domain')
    const { token } = await login(app, { email, password: 'ncc-1701' })
    const orderId = security.hash(email).slice(0, 4) + '-0123456789abcdef'
    await ordersCollection.insert({ orderId, email: email.replace(/[aeiou]/gi, '*'), userId: 999999 })
    const pdfFile = path.join(ORDERS_DIR, `order_${orderId}.pdf`)
    await fs.promises.mkdir(ORDERS_DIR, { recursive: true })
    await fs.promises.writeFile(pdfFile, '%PDF-1.3')

    try {
      const res = await request(app)
        .get(`/rest/order-history/${orderId}/confirmation`)
        .set({ Authorization: 'Bearer ' + token })

      assert.equal(res.status, 404)
    } finally {
      await fs.promises.rm(pdfFile, { force: true })
    }
  })

  void it('GET order confirmation PDF is not exposed via /ftp', async () => {
    const { orderId } = await placeOrder('jim@' + config.get<string>('application.domain'), 'ncc-1701', 2)

    const listing = await request(app).get('/ftp')
    assert.ok(!listing.text.includes(`order_${orderId}.pdf`))

    const res = await request(app).get(`/ftp/order_${orderId}.pdf`)
    assert.notEqual(res.status, 200)
  })
})
