/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

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

  void it('GET order history does not include orders of a user with a vowel-colliding email', async () => {
    const email = 'odmin@' + config.get<string>('application.domain')
    const password = randomUUID()
    await register(app, { email, password })
    const { token } = await login(app, { email, password })

    const res = await request(app)
      .get('/rest/order-history')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })

    assert.equal(res.status, 200)
    assert.deepEqual(res.body.data, [])
  })

  void it('GET order history does not include orders for an account registered with the masked email of another user', async () => {
    const email = ('admin@' + config.get<string>('application.domain')).replace(/[aeiou]/gi, '*')
    const password = randomUUID()
    await register(app, { email, password })
    const { token } = await login(app, { email, password })

    const res = await request(app)
      .get('/rest/order-history')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })

    assert.equal(res.status, 200)
    assert.deepEqual(res.body.data, [])
  })

  void it('GET order history does not include a new order placed by a user whose email differs only in vowels', async () => {
    const suffix = randomUUID().replace(/[aeiou-]/gi, '')
    const ownerEmail = `alice${suffix}@acme.example`
    const lookAlikeEmail = `elico${suffix}@ocme.exomple`
    assert.equal(ownerEmail.replace(/[aeiou]/gi, '*'), lookAlikeEmail.replace(/[aeiou]/gi, '*'))

    const ownerPassword = randomUUID()
    await register(app, { email: ownerEmail, password: ownerPassword })
    const owner = await login(app, { email: ownerEmail, password: ownerPassword })
    const ownerHeader = { Authorization: 'Bearer ' + owner.token, 'content-type': 'application/json' }

    const itemRes = await request(app)
      .post('/api/BasketItems')
      .set(ownerHeader)
      .send({ BasketId: owner.bid, ProductId: 1, quantity: 1 })
    assert.equal(itemRes.status, 200)

    const checkoutRes = await request(app)
      .post(`/rest/basket/${owner.bid}/checkout`)
      .set(ownerHeader)
    assert.equal(checkoutRes.status, 200)
    const orderId = checkoutRes.body.orderConfirmation

    const ownerHistory = await request(app)
      .get('/rest/order-history')
      .set(ownerHeader)
    assert.equal(ownerHistory.status, 200)
    assert.deepEqual(ownerHistory.body.data.map((o: { orderId: string }) => o.orderId), [orderId])

    const lookAlikePassword = randomUUID()
    await register(app, { email: lookAlikeEmail, password: lookAlikePassword })
    const lookAlike = await login(app, { email: lookAlikeEmail, password: lookAlikePassword })

    const res = await request(app)
      .get('/rest/order-history')
      .set({ Authorization: 'Bearer ' + lookAlike.token, 'content-type': 'application/json' })

    assert.equal(res.status, 200)
    assert.deepEqual(res.body.data, [])
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
