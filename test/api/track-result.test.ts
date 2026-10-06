/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express
let adminAuth: { Authorization: string }
let jimAuth: { Authorization: string }
let adminOrderId: string

const obfuscatedAdminEmail = 'admin@juice-sh.op'.replace(/[aeiou]/gi, '*')

before(async () => {
  const result = await createTestApp()
  app = result.app

  const admin = await login(app, { email: 'admin@juice-sh.op', password: 'admin123' })
  adminAuth = { Authorization: 'Bearer ' + admin.token }
  const jim = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
  jimAuth = { Authorization: 'Bearer ' + jim.token }

  const history = await request(app).get('/rest/order-history').set(adminAuth)
  adminOrderId = history.body.data[0].orderId
}, { timeout: 60000 })

void describe('/rest/track-order/:id', () => {
  void it('GET tracking results is not allowed via public API', async () => {
    const res = await request(app)
      .get(`/rest/track-order/${adminOrderId}`)
    assert.equal(res.status, 401)
  })

  void it('GET tracking results for an own order id', async () => {
    const res = await request(app)
      .get(`/rest/track-order/${adminOrderId}`)
      .set(adminAuth)
    assert.equal(res.status, 200)
    assert.equal(res.body.data.length, 1)
    assert.equal(res.body.data[0].orderId, adminOrderId)
    assert.equal(res.body.data[0].email, obfuscatedAdminEmail)
  })

  void it('GET no tracking results for an order id of another user', async () => {
    const res = await request(app)
      .get(`/rest/track-order/${adminOrderId}`)
      .set(jimAuth)
    assert.equal(res.status, 200)
    assert.deepEqual(res.body.data, [{ orderId: adminOrderId }])
  })

  void it('GET no orders when injecting into orderId', async () => {
    const res = await request(app)
      .get('/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27')
      .set(adminAuth)
    assert.equal(res.status, 200)
    assert.deepEqual(res.body.data, [{ orderId: 'true' }])
  })

  void it('GET sanitized order id reflected back without markup', async () => {
    const res = await request(app)
      .get(`/rest/track-order/${encodeURIComponent('<iframe src="javascript:alert(`xss`)">')}`)
      .set(adminAuth)
    assert.equal(res.status, 200)
    assert.deepEqual(res.body.data, [{ orderId: 'iframesrcjavascriptalertxss' }])
  })
})
