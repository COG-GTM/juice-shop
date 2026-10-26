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
let ownerHeader: { Authorization: string }
let otherUserHeader: { Authorization: string }
let orderId: string

before(async () => {
  const result = await createTestApp()
  app = result.app

  const owner = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
  ownerHeader = { Authorization: 'Bearer ' + owner.token }
  const other = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
  otherUserHeader = { Authorization: 'Bearer ' + other.token }

  const res = await request(app).post('/rest/basket/2/checkout').set(ownerHeader)
  assert.equal(res.status, 200)
  orderId = res.body.orderConfirmation
}, { timeout: 60000 })

void describe('/rest/order-history/:id/confirmation', () => {
  void it('GET order confirmation PDF as the ordering user', async () => {
    const res = await request(app)
      .get(`/rest/order-history/${orderId}/confirmation`)
      .set(ownerHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/pdf'))
  })

  void it('GET order confirmation PDF without authentication is denied', async () => {
    const res = await request(app)
      .get(`/rest/order-history/${orderId}/confirmation`)
    assert.equal(res.status, 401)
  })

  void it('GET order confirmation PDF of another user returns a 404 error', async () => {
    const res = await request(app)
      .get(`/rest/order-history/${orderId}/confirmation`)
      .set(otherUserHeader)
    assert.equal(res.status, 404)
  })

  void it('GET order confirmation PDF with a malformed order id returns a 404 error', async () => {
    const res = await request(app)
      .get('/rest/order-history/..%2F..%2Fpackage.json/confirmation')
      .set(ownerHeader)
    assert.equal(res.status, 404)
  })

  void it('GET order confirmation PDF is not served from the public /ftp folder', async () => {
    const res = await request(app)
      .get(`/ftp/order_${orderId}.pdf`)
    assert.equal(res.status, 404)
  })
})
