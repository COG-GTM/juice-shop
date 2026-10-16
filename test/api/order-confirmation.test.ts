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

  const jim = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
  jimToken = jim.token
  benderToken = (await login(app, { email: 'bender@juice-sh.op', password: 'OhG0dPlease1nsertLiquor!' })).token

  const checkout = await request(app)
    .post(`/rest/basket/${jim.bid}/checkout`)
    .set({ Authorization: 'Bearer ' + jimToken, 'content-type': 'application/json' })
  assert.equal(checkout.status, 200)
  orderId = checkout.body.orderConfirmation
}, { timeout: 60000 })

void describe('order confirmation PDFs', () => {
  void it('are not listed in the public /ftp directory', async () => {
    const res = await request(app).get('/ftp')
    assert.equal(res.status, 200)
    assert.ok(!res.text.includes('order_'))
  })

  void it('cannot be downloaded from the public /ftp directory', async () => {
    const res = await request(app).get(`/ftp/order_${orderId}.pdf`)
    assert.equal(res.status, 404)
  })
})

void describe('/rest/order-confirmation/:orderId', () => {
  void it('GET without authentication is denied', async () => {
    const res = await request(app).get(`/rest/order-confirmation/${orderId}`)
    assert.equal(res.status, 401)
  })

  void it('GET another customer\'s order confirmation is not found', async () => {
    const res = await request(app)
      .get(`/rest/order-confirmation/${orderId}`)
      .set('Authorization', 'Bearer ' + benderToken)
    assert.equal(res.status, 404)
  })

  void it('GET own order confirmation with bearer token returns the PDF', async () => {
    const res = await request(app)
      .get(`/rest/order-confirmation/${orderId}`)
      .set('Authorization', 'Bearer ' + jimToken)
      .buffer(true)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/pdf'))
    assert.equal(res.headers['cache-control'], 'private, no-store')
  })

  void it('GET own order confirmation with token cookie returns the PDF', async () => {
    const res = await request(app)
      .get(`/rest/order-confirmation/${orderId}`)
      .set('Cookie', 'token=' + jimToken)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/pdf'))
  })

  void it('GET with a malformed order id is not found', async () => {
    const res = await request(app)
      .get('/rest/order-confirmation/..%2F..%2Fpackage.json')
      .set('Authorization', 'Bearer ' + jimToken)
    assert.equal(res.status, 404)
  })
})
