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
let seededOrderId: string

before(async () => {
  const result = await createTestApp()
  app = result.app
  const seededOrders = await ordersCollection.find()
  seededOrderId = seededOrders[0].orderId
}, { timeout: 60000 })

void describe('/rest/track-order/:id', () => {
  void it('GET tracking results for the order id', async () => {
    const res = await request(app)
      .get(`/rest/track-order/${seededOrderId}`)
    assert.equal(res.status, 200)
    assert.equal(res.body.data[0].orderId, seededOrderId)
    assert.equal(typeof res.body.data[0].email, 'string')
  })

  void it('does not allow NoSQL injection into orderId', async () => {
    const res = await request(app)
      .get('/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27')
    assert.equal(res.status, 200)
    assert.equal(res.body.data.length, 1)
    assert.deepEqual(res.body.data[0], { orderId: 'true' })
  })

  void it('strips HTML characters from orderId', async () => {
    const res = await request(app)
      .get('/rest/track-order/%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E')
    assert.equal(res.status, 200)
    assert.equal(res.body.data[0].orderId, 'imgsrcxonerroralert1')
  })
})
