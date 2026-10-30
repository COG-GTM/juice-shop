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
let otherHeader: { Authorization: string }
let orderId: string

before(async () => {
  const result = await createTestApp()
  app = result.app

  const owner = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
  ownerHeader = { Authorization: 'Bearer ' + owner.token }
  const other = await login(app, { email: 'bender@juice-sh.op', password: 'OhG0dPlease1nsertLiquor!' })
  otherHeader = { Authorization: 'Bearer ' + other.token }

  const res = await request(app).post('/rest/basket/2/checkout').set(ownerHeader)
  assert.equal(res.status, 200)
  orderId = res.body.orderConfirmation
}, { timeout: 60000 })

void describe('/rest/order-history/:id/confirmation', () => {
  void it('GET order confirmation is not allowed for anonymous users', async () => {
    const res = await request(app).get(`/rest/order-history/${orderId}/confirmation`)
    assert.equal(res.status, 401)
  })

  void it('GET order confirmation of another customer is not found', async () => {
    const res = await request(app).get(`/rest/order-history/${orderId}/confirmation`).set(otherHeader)
    assert.equal(res.status, 404)
  })

  void it('GET order confirmation with malformed order id is not found', async () => {
    const res = await request(app).get('/rest/order-history/..%2F..%2Fpackage.json/confirmation').set(ownerHeader)
    assert.equal(res.status, 404)
  })

  void it('GET own order confirmation returns the PDF', async () => {
    const res = await request(app).get(`/rest/order-history/${orderId}/confirmation`).set(ownerHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/pdf'))
  })
})

void describe('/ftp', () => {
  void it('GET order confirmation from public /ftp folder is forbidden', async () => {
    const res = await request(app).get(`/ftp/order_${orderId}.pdf`)
    assert.equal(res.status, 403)
  })

  void it('GET directory listing of /ftp does not list order confirmations', async () => {
    const res = await request(app).get('/ftp')
    assert.equal(res.status, 200)
    assert.ok(!res.text.includes(`order_${orderId}.pdf`))
  })
})
