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
import { login, register } from './helpers/auth'

let app: Express
let collidingUserToken: string
let collidingUserBasketId: number

before(async () => {
  const result = await createTestApp()
  app = result.app
  const collidingEmail = 'odmen@' + config.get<string>('application.domain')
  await register(app, { email: collidingEmail, password: 'collision123' })
  const { token, bid } = await login(app, { email: collidingEmail, password: 'collision123' })
  collidingUserToken = token
  collidingUserBasketId = bid
}, { timeout: 60000 })

void describe('orders of users with colliding vowel-masked emails', () => {
  void it('GET /rest/order-history does not return orders of another user', async () => {
    const res = await request(app)
      .get('/rest/order-history')
      .set({ Authorization: 'Bearer ' + collidingUserToken, 'content-type': 'application/json' })

    assert.equal(res.status, 200)
    assert.deepEqual(res.body.data, [])
  })

  void it('POST /rest/user/data-export does not include orders of another user', async () => {
    const res = await request(app)
      .post('/rest/user/data-export')
      .set({ Authorization: 'Bearer ' + collidingUserToken, 'content-type': 'application/json' })
      .send({ format: '1' })

    assert.equal(res.status, 200)
    assert.deepEqual(JSON.parse(res.body.userData).orders, [])
  })

  void it('orders placed by a user appear in their own history and data export', async () => {
    const authHeader = { Authorization: 'Bearer ' + collidingUserToken, 'content-type': 'application/json' }
    await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: collidingUserBasketId, ProductId: 1, quantity: 1 })
      .expect(200)
    const checkout = await request(app)
      .post(`/rest/basket/${collidingUserBasketId}/checkout`)
      .set(authHeader)
      .expect(200)

    const history = await request(app)
      .get('/rest/order-history')
      .set(authHeader)
    assert.equal(history.status, 200)
    assert.deepEqual(history.body.data.map((order: { orderId: string }) => order.orderId), [checkout.body.orderConfirmation])

    const exported = await request(app)
      .post('/rest/user/data-export')
      .set(authHeader)
      .send({ format: '1' })
    assert.equal(exported.status, 200)
    assert.deepEqual(JSON.parse(exported.body.userData).orders.map((order: { orderId: string }) => order.orderId), [checkout.body.orderConfirmation])
  })
})
