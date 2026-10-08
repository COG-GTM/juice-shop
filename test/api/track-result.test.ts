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

  void it('GET no orders when injecting a $where expression into orderId', async () => {
    const res = await request(app)
      .get('/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27')
    assert.equal(res.status, 400)
    assert.deepEqual(res.body, { error: 'Invalid order id' })
  })

  void it('GET rejects a busy-loop payload without evaluating it', async () => {
    const res = await request(app)
      .get(`/rest/track-order/${encodeURIComponent("';while(1){}'")}`)
    assert.equal(res.status, 400)
  })

  void it('GET rejects markup in the order id instead of reflecting it', async () => {
    const res = await request(app)
      .get(`/rest/track-order/${encodeURIComponent('<iframe src="javascript:alert(`xss`)">')}`)
    assert.equal(res.status, 400)
    assert.ok(!JSON.stringify(res.body).includes('iframe'))
  })

  void it('GET placeholder for a well-formed but unknown order id', async () => {
    const res = await request(app)
      .get('/rest/track-order/0000-0000000000000000')
    assert.equal(res.status, 200)
    assert.deepEqual(res.body.data, [{ orderId: '0000-0000000000000000' }])
  })
})
