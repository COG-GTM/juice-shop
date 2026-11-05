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
let jimToken: string
let benderToken: string
let orderId: string

before(async () => {
  const result = await createTestApp()
  app = result.app

  jimToken = (await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })).token
  benderToken = (await login(app, { email: 'bender@juice-sh.op', password: 'OhG0dPlease1nsertLiquor!' })).token

  const res = await request(app)
    .post('/rest/basket/2/checkout')
    .set({ Authorization: 'Bearer ' + jimToken, 'content-type': 'application/json' })
  assert.equal(res.status, 200)
  orderId = res.body.orderConfirmation
}, { timeout: 60000 })

void describe('/rest/order-history/:id/confirmation', () => {
  void it('GET order confirmation PDF is denied without authentication', async () => {
    const res = await request(app).get(`/rest/order-history/${orderId}/confirmation`)
    assert.equal(res.status, 401)
  })

  void it('GET own order confirmation PDF via Authorization header', async () => {
    const res = await request(app)
      .get(`/rest/order-history/${orderId}/confirmation`)
      .set({ Authorization: 'Bearer ' + jimToken })
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/pdf'))
  })

  void it('GET own order confirmation PDF via token cookie', async () => {
    const res = await request(app)
      .get(`/rest/order-history/${orderId}/confirmation`)
      .set('Cookie', 'token=' + jimToken)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/pdf'))
  })

  void it('GET order confirmation PDF of another customer is denied', async () => {
    const res = await request(app)
      .get(`/rest/order-history/${orderId}/confirmation`)
      .set({ Authorization: 'Bearer ' + benderToken })
    assert.equal(res.status, 404)
  })

  void it('GET order confirmation PDF with malformed order id is denied', async () => {
    const res = await request(app)
      .get('/rest/order-history/..%2F..%2Fpackage.json/confirmation')
      .set({ Authorization: 'Bearer ' + jimToken })
    assert.equal(res.status, 404)
  })
})

void describe('/ftp', () => {
  void it('GET directory listing does not contain order confirmation PDFs', async () => {
    const res = await request(app).get('/ftp')
    assert.equal(res.status, 200)
    assert.ok(!res.text.includes('order_'))
  })

  void it('GET order confirmation PDF is not served from /ftp', async () => {
    const res = await request(app).get(`/ftp/order_${orderId}.pdf`)
    assert.notEqual(res.status, 200)
  })
})
