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
let bjoernToken: string
let orderId: string

before(
  async () => {
    const result = await createTestApp()
    app = result.app
    jimToken = (await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })).token
    bjoernToken = (await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })).token

    const res = await request(app).post('/rest/basket/2/checkout').set('Authorization', 'Bearer ' + jimToken)
    assert.equal(res.status, 200)
    orderId = res.body.orderConfirmation
  },
  { timeout: 60000 }
)

void describe('/rest/order-confirmation/:id', () => {
  void it('GET order confirmation PDF is not possible without authentication', async () => {
    const res = await request(app).get('/rest/order-confirmation/' + orderId)
    assert.equal(res.status, 401)
  })

  void it('GET order confirmation PDF as the ordering customer', async () => {
    const res = await request(app).get('/rest/order-confirmation/' + orderId).set('Authorization', 'Bearer ' + jimToken)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/pdf'))
  })

  void it('GET order confirmation PDF via token cookie as the ordering customer', async () => {
    const res = await request(app).get('/rest/order-confirmation/' + orderId).set('Cookie', 'token=' + jimToken)
    assert.equal(res.status, 200)
  })

  void it('GET order confirmation PDF of another customer is not possible', async () => {
    const res = await request(app).get('/rest/order-confirmation/' + orderId).set('Authorization', 'Bearer ' + bjoernToken)
    assert.equal(res.status, 404)
  })

  void it('GET order confirmation PDF with unsigned token is not possible', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')
    const payload = Buffer.from(JSON.stringify({ data: { id: 2, email: 'jim@juice-sh.op' } })).toString('base64url')
    const res = await request(app).get('/rest/order-confirmation/' + orderId).set('Authorization', `Bearer ${header}.${payload}.`)
    assert.equal(res.status, 401)
  })

  void it('GET order confirmation PDF with RS256 token carrying a forged signature is not possible', async () => {
    const [header, payload, signature] = jimToken.split('.')
    const forgedPayload = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(payload, 'base64url').toString()), iat: 0 })).toString('base64url')
    const res = await request(app).get('/rest/order-confirmation/' + orderId).set('Authorization', `Bearer ${header}.${forgedPayload}.${signature}`)
    assert.equal(res.status, 401)
  })

  void it('GET order confirmation PDF with malformed order id is rejected', async () => {
    const res = await request(app).get('/rest/order-confirmation/..%2F..%2Fpackage.json').set('Authorization', 'Bearer ' + jimToken)
    assert.equal(res.status, 400)
  })

  void it('GET order confirmation PDF is no longer listed in or served from /ftp', async () => {
    const listing = await request(app).get('/ftp')
    assert.ok(!listing.text.includes('order_'))
    const res = await request(app).get(`/ftp/order_${orderId}.pdf`)
    assert.notEqual(res.status, 200)
  })
})
