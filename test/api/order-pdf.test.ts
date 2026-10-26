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

before(
  async () => {
    const result = await createTestApp()
    app = result.app

    const jim = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
    const bender = await login(app, { email: 'bender@juice-sh.op', password: 'OhG0dPlease1nsertLiquor!' })
    jimAuth = { Authorization: 'Bearer ' + jim.token }
    benderAuth = { Authorization: 'Bearer ' + bender.token }

    const res = await request(app).post('/rest/basket/2/checkout').set(jimAuth)
    assert.equal(res.status, 200)
    orderId = res.body.orderConfirmation
  },
  { timeout: 60000 }
)

void describe('/rest/order/:orderId/pdf', () => {
  void it('GET order confirmation PDF as its owner', async () => {
    const res = await request(app).get(`/rest/order/${orderId}/pdf`).set(jimAuth)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/pdf'))
  })

  void it('GET order confirmation PDF without authentication is refused', async () => {
    const res = await request(app).get(`/rest/order/${orderId}/pdf`)
    assert.equal(res.status, 401)
  })

  void it('GET order confirmation PDF of another user is refused', async () => {
    const res = await request(app).get(`/rest/order/${orderId}/pdf`).set(benderAuth)
    assert.equal(res.status, 404)
  })

  void it('GET order confirmation PDF with malformed order id is refused', async () => {
    const res = await request(app).get('/rest/order/..%2F..%2Fpackage.json/pdf').set(jimAuth)
    assert.equal(res.status, 400)
  })
})

void describe('/ftp', () => {
  void it('GET directory listing does not reveal order confirmation PDFs', async () => {
    const res = await request(app).get('/ftp')
    assert.equal(res.status, 200)
    assert.ok(!res.text.includes(`order_${orderId}.pdf`))
  })

  void it('GET order confirmation PDF via public /ftp folder fails', async () => {
    const res = await request(app).get(`/ftp/order_${orderId}.pdf`)
    assert.notEqual(res.status, 200)
  })
})
