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

void describe('/rest/track-order/:id', () => {
  void it('GET tracking results for the order id', async () => {
    const res = await request(app)
      .get('/rest/track-order/5267-f9cd5882f54c75a3')
    assert.equal(res.status, 200)
  })

  void it('GET own order by its order id', async () => {
    const { token } = await login(app, {
      email: 'admin@' + config.get<string>('application.domain'),
      password: 'admin123'
    })
    const history = await request(app)
      .get('/rest/order-history')
      .set({ Authorization: 'Bearer ' + token })
    const orderId = history.body.data[0].orderId

    const res = await request(app)
      .get(`/rest/track-order/${orderId}`)
    assert.equal(res.status, 200)
    assert.equal(res.body.data.length, 1)
    assert.equal(res.body.data[0].orderId, orderId)
    assert.equal(res.body.data[0].totalPrice, history.body.data[0].totalPrice)
  })

  void it('GET no orders when injecting into orderId', async () => {
    const res = await request(app)
      .get('/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27')
    assert.equal(res.status, 200)
    assert.equal(res.body.data.length, 1)
    assert.deepEqual(Object.keys(res.body.data[0]), ['orderId'])
  })

  void it('GET no orders when injecting a $where expression that returns true', async () => {
    const res = await request(app)
      .get(`/rest/track-order/${encodeURIComponent("';return true;//")}`)
    assert.equal(res.status, 200)
    assert.equal(res.body.data.length, 1)
    assert.deepEqual(Object.keys(res.body.data[0]), ['orderId'])
  })
})
