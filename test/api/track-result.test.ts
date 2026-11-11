/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

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

  void it('GET rejects NoSQL injection attempts in orderId', async () => {
    const res = await request(app)
      .get('/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27')
    assert.equal(res.status, 400)
  })

  void it('GET rejects HTML in orderId instead of reflecting it', async () => {
    const res = await request(app)
      .get('/rest/track-order/%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E')
    assert.equal(res.status, 400)
    assert.ok(!JSON.stringify(res.body).includes('<img'))
  })

  void it('GET echoes a well-formed unknown orderId as JSON', async () => {
    const res = await request(app)
      .get('/rest/track-order/0000-0000000000000000')
    assert.equal(res.status, 200)
    assert.equal(res.body.data[0].orderId, '0000-0000000000000000')
  })
})
