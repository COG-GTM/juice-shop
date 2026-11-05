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
import * as security from '../../lib/insecurity'

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
  let orderId: string
  let jimToken: string

  before(async () => {
    const authentication = await login(app, {
      email: 'jim@' + config.get<string>('application.domain'),
      password: 'ncc-1701'
    })
    jimToken = authentication.token
    const res = await request(app)
      .post(`/rest/basket/${authentication.bid}/checkout`)
      .set({ Authorization: 'Bearer ' + jimToken, 'content-type': 'application/json' })
    assert.equal(res.status, 200)
    orderId = res.body.orderConfirmation
  })

  void it('GET own order confirmation PDF', async () => {
    const res = await request(app)
      .get(`/rest/order-history/${orderId}/confirmation`)
      .set({ Authorization: 'Bearer ' + jimToken })
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/pdf'))
  })

  void it('GET own order confirmation PDF with token cookie', async () => {
    const res = await request(app)
      .get(`/rest/order-history/${orderId}/confirmation`)
      .set('Cookie', 'token=' + jimToken)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/pdf'))
  })

  void it('GET order confirmation PDF of another user is forbidden', async () => {
    const { token } = await login(app, {
      email: 'admin@' + config.get<string>('application.domain'),
      password: 'admin123'
    })
    const res = await request(app)
      .get(`/rest/order-history/${orderId}/confirmation`)
      .set({ Authorization: 'Bearer ' + token })
    assert.equal(res.status, 403)
  })

  void it('GET order confirmation PDF without authentication is denied', async () => {
    const res = await request(app)
      .get(`/rest/order-history/${orderId}/confirmation`)
    assert.equal(res.status, 401)
  })

  void it('GET order confirmation PDF with token not issued by login is denied', async () => {
    const res = await request(app)
      .get(`/rest/order-history/${orderId}/confirmation`)
      .set({ Authorization: 'Bearer ' + security.authorize({ data: { id: 2, email: 'jim@juice-sh.op' } }) })
    assert.equal(res.status, 401)
  })

  void it('GET order confirmation PDF with malformed order id is rejected', async () => {
    const res = await request(app)
      .get('/rest/order-history/..%2F..%2Fpackage.json/confirmation')
      .set({ Authorization: 'Bearer ' + jimToken })
    assert.equal(res.status, 400)
  })

  void it('GET order confirmation PDF is no longer publicly served from /ftp', async () => {
    const res = await request(app)
      .get(`/ftp/order_${orderId}.pdf`)
    assert.equal(res.status, 404)
  })
})
