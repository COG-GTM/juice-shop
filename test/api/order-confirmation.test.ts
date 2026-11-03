/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { before, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import request from 'supertest'
import jwt from 'jsonwebtoken'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import { privateKey } from '../../lib/insecurity'
import * as security from '../../lib/insecurity'
import * as db from '../../data/mongodb'
import { orderConfirmationDirectory } from '../../routes/order'

let app: Express
let ownerToken: string
let otherUserToken: string
let orderId: string

before(async () => {
  const result = await createTestApp()
  app = result.app

  const owner = await login(app, {
    email: 'jim@' + config.get<string>('application.domain'),
    password: 'ncc-1701'
  })
  ownerToken = owner.token

  const otherUser = await login(app, {
    email: 'bjoern.kimminich@gmail.com',
    password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
  })
  otherUserToken = otherUser.token

  const checkout = await request(app)
    .post('/rest/basket/1/checkout')
    .set({ Authorization: 'Bearer ' + ownerToken })
  assert.equal(checkout.status, 200)
  orderId = checkout.body.orderConfirmation
}, { timeout: 60000 })

void describe('/rest/order-history/:id/confirmation', () => {
  void it('keeps order PDFs out of the public FTP area', async () => {
    assert.equal(fs.existsSync(path.join(orderConfirmationDirectory, `order_${orderId}.pdf`)), true)

    const fileResponse = await request(app).get(`/ftp/order_${orderId}.pdf`)
    assert.equal(fileResponse.status, 404)

    const listing = await request(app).get('/ftp')
    assert.equal(listing.status, 200)
    assert.equal(listing.text.includes(`order_${orderId}`), false)
  })

  void it('serves the confirmation PDF to its owner with a bearer token', async () => {
    const res = await request(app)
      .get(`/rest/order-history/${orderId}/confirmation`)
      .set({ Authorization: 'Bearer ' + ownerToken })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/pdf'))
    assert.ok(res.headers['cache-control']?.includes('no-store'))
  })

  void it('serves the confirmation PDF to its owner with a token cookie', async () => {
    const res = await request(app)
      .get(`/rest/order-history/${orderId}/confirmation`)
      .set({ Cookie: `token=${ownerToken}` })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/pdf'))
  })

  void it('rejects anonymous requests', async () => {
    const res = await request(app).get(`/rest/order-history/${orderId}/confirmation`)
    assert.equal(res.status, 401)
  })

  void it('does not serve another user’s order confirmation', async () => {
    const res = await request(app)
      .get(`/rest/order-history/${orderId}/confirmation`)
      .set({ Authorization: 'Bearer ' + otherUserToken })
    assert.equal(res.status, 404)
  })

  void it('returns 404 when an owned order has no stored PDF', async () => {
    const user = security.authenticatedUsers.get(ownerToken)
    assert.ok(user?.data.id)
    const missingPdfOrderId = 'ffff-ffffffffffffffff'
    await db.ordersCollection.insert({ orderId: missingPdfOrderId, userId: user.data.id })

    const res = await request(app)
      .get(`/rest/order-history/${missingPdfOrderId}/confirmation`)
      .set({ Authorization: 'Bearer ' + ownerToken })
    assert.equal(res.status, 404)
  })

  void it('rejects malformed order IDs', async () => {
    const malformed = await request(app)
      .get('/rest/order-history/abc/confirmation')
      .set({ Authorization: 'Bearer ' + ownerToken })
    assert.equal(malformed.status, 400)

    const traversal = await request(app)
      .get('/rest/order-history/..%2f..%2fpackage.json/confirmation')
      .set({ Authorization: 'Bearer ' + ownerToken })
    assert.equal(traversal.status, 400)
  })

  void it('rejects expired tokens for the order owner', async () => {
    const owner = security.authenticatedUsers.get(ownerToken)
    assert.ok(owner?.data.id)
    const expiredToken = jwt.sign({
      ...owner.data,
      exp: Math.floor(Date.now() / 1000) - 1
    }, privateKey, { algorithm: 'RS256' })
    security.authenticatedUsers.put(expiredToken, owner)
    assert.equal(security.verify(expiredToken), true)

    const res = await request(app)
      .get(`/rest/order-history/${orderId}/confirmation`)
      .set({ Authorization: 'Bearer ' + expiredToken })

    assert.equal(res.status, 401)
  })
})
