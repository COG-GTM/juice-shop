/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express
let ownerToken: string
let otherToken: string
let orderId: string

before(async () => {
  const result = await createTestApp()
  app = result.app
  const owner = await login(app, {
    email: 'admin@' + config.get<string>('application.domain'),
    password: 'admin123'
  })
  ownerToken = owner.token
  const other = await login(app, {
    email: 'jim@' + config.get<string>('application.domain'),
    password: 'ncc-1701'
  })
  otherToken = other.token
  const res = await request(app)
    .post(`/rest/basket/${owner.bid}/checkout`)
    .set({ Authorization: 'Bearer ' + ownerToken })
  assert.equal(res.status, 200)
  orderId = res.body.orderConfirmation
}, { timeout: 60000 })

void describe('/rest/order-confirmation/:id', () => {
  void it('does not write the order confirmation into the public ftp folder', async () => {
    assert.equal(fs.existsSync(`ftp/order_${orderId}.pdf`), false)
    assert.equal(fs.existsSync(`orders/order_${orderId}.pdf`), true)
  })

  void it('GET order confirmation via /ftp is not possible', async () => {
    const res = await request(app)
      .get(`/ftp/order_${orderId}.pdf`)
    assert.equal(res.status, 404)
  })

  void it('GET order confirmation without token is denied', async () => {
    const res = await request(app)
      .get(`/rest/order-confirmation/${orderId}`)
    assert.equal(res.status, 401)
  })

  void it('GET order confirmation of another user is forbidden', async () => {
    const res = await request(app)
      .get(`/rest/order-confirmation/${orderId}`)
      .set({ Authorization: 'Bearer ' + otherToken })
    assert.equal(res.status, 403)
  })

  void it('GET order confirmation with malformed id is rejected', async () => {
    const res = await request(app)
      .get('/rest/order-confirmation/..%2F..%2Fpackage.json')
      .set({ Authorization: 'Bearer ' + ownerToken })
    assert.equal(res.status, 400)
  })

  void it('GET own order confirmation returns the PDF', async () => {
    const res = await request(app)
      .get(`/rest/order-confirmation/${orderId}`)
      .set({ Authorization: 'Bearer ' + ownerToken })
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/pdf'))
  })
})
