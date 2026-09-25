/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { ordersCollection } from '../../data/mongodb'

let app: Express
let seededOrder: { orderId: string, email: string }

before(async () => {
  const result = await createTestApp()
  app = result.app
  const orders = await ordersCollection.find({})
  seededOrder = orders[0]
}, { timeout: 60000 })

void describe('/rest/track-order/:id', () => {
  void it('GET tracking results for the order id', async () => {
    const res = await request(app)
      .get(`/rest/track-order/${seededOrder.orderId}`)
    assert.equal(res.status, 200)
    assert.equal(res.body.data.length, 1)
    assert.equal(res.body.data[0].orderId, seededOrder.orderId)
    assert.equal(res.body.data[0].email, seededOrder.email)
  })

  void it('GET no orders when injecting into orderId', async () => {
    const res = await request(app)
      .get('/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.ok(Array.isArray(res.body.data))
    assert.equal(res.body.data.length, 1)
    assert.equal(res.body.data[0].email, undefined)
    assert.ok((await ordersCollection.find({})).length > 1)
  })
})
