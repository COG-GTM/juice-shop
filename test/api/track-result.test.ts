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
let authHeader: { Authorization: string, 'content-type': string }

const adminEmail = 'admin@juice-sh.op'
const obfuscatedAdminEmail = adminEmail.replace(/[aeiou]/gi, '*')

before(async () => {
  const result = await createTestApp()
  app = result.app

  const { token } = await login(app, {
    email: adminEmail,
    password: 'admin123'
  })
  authHeader = {
    Authorization: 'Bearer ' + token,
    'content-type': 'application/json'
  }
}, { timeout: 60000 })

void describe('/rest/track-order/:id', () => {
  void it('GET tracking results is not allowed via public API', async () => {
    const res = await request(app)
      .get('/rest/track-order/5267-f9cd5882f54c75a3')
    assert.equal(res.status, 401)
  })

  void it('GET tracking results for the order id', async () => {
    const res = await request(app)
      .get('/rest/track-order/5267-f9cd5882f54c75a3')
      .set(authHeader)
    assert.equal(res.status, 200)
  })

  void it('GET tracking results with a lowercase bearer scheme', async () => {
    const res = await request(app)
      .get('/rest/track-order/5267-f9cd5882f54c75a3')
      .set({ ...authHeader, Authorization: authHeader.Authorization.replace('Bearer', 'bearer') })
    assert.equal(res.status, 200)
  })

  void it('GET only own orders when injecting into orderId', async () => {
    const res = await request(app)
      .get('/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27')
      .set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.ok(Array.isArray(res.body.data))
    for (const item of res.body.data) {
      assert.equal(item.email, obfuscatedAdminEmail)
    }
  })
})
