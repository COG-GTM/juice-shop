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

  void it('GET rejects attempts to inject into orderId', async () => {
    for (const payload of ["' || true || '", "'; return true; //", "' || this.orderId.match(/.*/) || '"]) {
      const res = await request(app)
        .get(`/rest/track-order/${encodeURIComponent(payload)}`)
      assert.equal(res.status, 400)
      assert.equal(res.body.error, 'Wrong Param')
    }
  })

  void it('GET tracking results for an unknown order id echo only that id', async () => {
    const res = await request(app)
      .get('/rest/track-order/does-not-exist')
    assert.equal(res.status, 200)
    assert.equal(res.body.data.length, 1)
    assert.deepEqual(res.body.data[0], { orderId: 'does-not-exist' })
  })
})
