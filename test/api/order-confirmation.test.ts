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
let jimAuth: { Authorization: string }
let benderAuth: { Authorization: string }
let orderId: string

before(async () => {
  const result = await createTestApp()
  app = result.app

  const jim = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
  jimAuth = { Authorization: 'Bearer ' + jim.token }
  const bender = await login(app, { email: 'bender@juice-sh.op', password: 'OhG0dPlease1nsertLiquor!' })
  benderAuth = { Authorization: 'Bearer ' + bender.token }

  const res = await request(app).post('/rest/basket/2/checkout').set(jimAuth)
  assert.equal(res.status, 200)
  orderId = res.body.orderConfirmation
}, { timeout: 60000 })

void describe('/rest/order-confirmation/:id', () => {
  void it('GET own order confirmation PDF as its customer', async () => {
    const res = await request(app)
      .get(`/rest/order-confirmation/${orderId}`)
      .set(jimAuth)
      .buffer(true)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/pdf'))
  })

  void it('GET order confirmation without being logged in is denied', async () => {
    const res = await request(app)
      .get(`/rest/order-confirmation/${orderId}`)
    assert.equal(res.status, 401)
  })

  void it('GET order confirmation of another customer is denied', async () => {
    const res = await request(app)
      .get(`/rest/order-confirmation/${orderId}`)
      .set(benderAuth)
    assert.equal(res.status, 404)
  })

  void it('GET order confirmation with path traversal in order id is rejected', async () => {
    const res = await request(app)
      .get('/rest/order-confirmation/..%2F..%2Fpackage.json')
      .set(jimAuth)
    assert.equal(res.status, 400)
  })

  void it('GET order confirmation PDF is no longer served from /ftp', async () => {
    const res = await request(app)
      .get(`/ftp/order_${orderId}.pdf`)
    assert.equal(res.status, 403)
  })
})
