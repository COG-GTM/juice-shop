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
let adminToken: string
let orderId: string

before(async () => {
  const result = await createTestApp()
  app = result.app

  jimToken = (await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })).token
  adminToken = (await login(app, { email: 'admin@juice-sh.op', password: 'admin123' })).token

  orderId = await placeOrder()
}, { timeout: 60000 })

async function placeOrder (): Promise<string> {
  const res = await request(app)
    .post('/rest/basket/2/checkout')
    .set({ Authorization: 'Bearer ' + jimToken, 'content-type': 'application/json' })
  assert.equal(res.status, 200)
  return res.body.orderConfirmation
}

void describe('/rest/order-confirmation/:id', () => {
  void it('GET order confirmation PDF as the ordering customer via Authorization header', async () => {
    const orderId = await placeOrder()
    const res = await request(app)
      .get(`/rest/order-confirmation/${orderId}`)
      .set('Authorization', 'Bearer ' + jimToken)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/pdf'))
  })

  void it('GET order confirmation PDF as the ordering customer via token cookie', async () => {
    const orderId = await placeOrder()
    const res = await request(app)
      .get(`/rest/order-confirmation/${orderId}`)
      .set('Cookie', `token=${jimToken}`)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/pdf'))
  })

  void it('GET order confirmation PDF without authentication is denied', async () => {
    const res = await request(app)
      .get(`/rest/order-confirmation/${orderId}`)
    assert.equal(res.status, 401)
  })

  void it('GET order confirmation PDF with an invalid token is denied', async () => {
    const res = await request(app)
      .get(`/rest/order-confirmation/${orderId}`)
      .set('Authorization', 'Bearer ' + jimToken.slice(0, -4) + 'AAAA')
    assert.equal(res.status, 401)
  })

  void it('GET order confirmation PDF of another customer is not found', async () => {
    const res = await request(app)
      .get(`/rest/order-confirmation/${orderId}`)
      .set('Authorization', 'Bearer ' + adminToken)
    assert.equal(res.status, 404)
  })

  void it('GET order confirmation with malformed order id is not found', async () => {
    const res = await request(app)
      .get('/rest/order-confirmation/..%2F..%2Fftp%2Facquisitions.md')
      .set('Authorization', 'Bearer ' + jimToken)
    assert.equal(res.status, 404)
  })
})

void describe('/ftp', () => {
  void it('GET directory listing does not reveal order confirmations', async () => {
    const res = await request(app).get('/ftp')
    assert.equal(res.status, 200)
    assert.ok(!res.text.includes(`order_${orderId}.pdf`))
  })

  void it('GET order confirmation PDF through /ftp is not found', async () => {
    const res = await request(app).get(`/ftp/order_${orderId}.pdf`)
    assert.equal(res.status, 404)
  })
})
