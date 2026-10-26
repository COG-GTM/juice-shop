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
    const { token } = await login(app, {
      email: 'admin@' + config.get<string>('application.domain'),
      password: 'admin123'
    })
    const orders = await request(app)
      .get('/rest/order-history')
      .set({ Authorization: 'Bearer ' + token })
    const orderId: string = orders.body.data[0].orderId

    const res = await request(app)
      .get('/rest/track-order/' + orderId)
    assert.equal(res.status, 200)
    assert.equal(res.body.data.length, 1)
    assert.equal(res.body.data[0].orderId, orderId)
  })

  void it('GET tracking results do not allow injecting into orderId', async () => {
    const res = await request(app)
      .get('/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27')
    assert.equal(res.status, 404)
    assert.deepEqual(res.body, { error: 'Order not found' })
  })

  void it('GET does not echo markup from an unknown order id', async () => {
    const res = await request(app)
      .get('/rest/track-order/' + encodeURIComponent('<iframe src="javascript:alert(`xss`)">'))
    assert.equal(res.status, 404)
    assert.deepEqual(res.body, { error: 'Order not found' })
    assert.ok(!res.text.includes('<'))
  })
})
