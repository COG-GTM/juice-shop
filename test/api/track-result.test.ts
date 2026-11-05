/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import * as db from '../../data/mongodb'

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

  void it('GET the matching order for an existing order id', async () => {
    const [order] = await db.ordersCollection.find({})
    const res = await request(app)
      .get(`/rest/track-order/${order.orderId}`)
    assert.equal(res.status, 200)
    assert.equal(res.body.data.length, 1)
    assert.equal(res.body.data[0].orderId, order.orderId)
    assert.equal(res.body.data[0].email, order.email)
  })

  void it('GET no orders when injecting into orderId', async () => {
    const res = await request(app)
      .get('/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27')
    assert.equal(res.status, 200)
    assert.equal(res.body.data.length, 1)
    assert.equal(res.body.data[0].orderId, 'true')
    assert.equal(res.body.data[0].email, undefined)
  })

  void it('GET does not evaluate JavaScript passed as orderId', { timeout: 10000 }, async () => {
    const res = await request(app)
      .get(`/rest/track-order/${encodeURIComponent("' || (()=>{while(1);})() || '")}`)
    assert.equal(res.status, 200)
    assert.equal(res.body.data.length, 1)
    assert.equal(res.body.data[0].email, undefined)
  })
})
