/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

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
    const { token } = await login(app, { email: email + '@' + config.get<string>('application.domain'), password })
    const headers = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
    const res = await request(app).post(`/rest/basket/${basketId}/checkout`).set(headers)
    assert.equal(res.status, 200)
    return { headers, orderId: res.body.orderConfirmation as string }
  }

  void it('GET order confirmation PDF is only available to the purchasing user', async () => {
    const { headers, orderId } = await placeOrder('jim', 'ncc-1701', 2)
    const { token: otherToken } = await login(app, { email: 'admin@' + config.get<string>('application.domain'), password: 'admin123' })

    const own = await request(app).get(`/rest/order-history/${orderId}/confirmation`).set(headers)
    assert.equal(own.status, 200)
    assert.ok(own.headers['content-type']?.includes('application/pdf'))

    const anonymous = await request(app).get(`/rest/order-history/${orderId}/confirmation`)
    assert.equal(anonymous.status, 401)

    const other = await request(app).get(`/rest/order-history/${orderId}/confirmation`).set({ Authorization: 'Bearer ' + otherToken })
    assert.equal(other.status, 404)

    const publicFtp = await request(app).get(`/ftp/order_${orderId}.pdf`)
    assert.equal(publicFtp.status, 403)
  })

  void it('GET order confirmation with malformed order id fails with 404 error', async () => {
    const { token } = await login(app, { email: 'admin@' + config.get<string>('application.domain'), password: 'admin123' })
    const res = await request(app).get('/rest/order-history/..%2f..%2fpackage.json/confirmation').set({ Authorization: 'Bearer ' + token })
    assert.equal(res.status, 404)
  })
})
