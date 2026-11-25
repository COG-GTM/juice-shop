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
let authHeader: { Authorization: string }

before(
  async () => {
    const result = await createTestApp()
    app = result.app

    const { token } = await login(app, {
      email: 'jim@juice-sh.op',
      password: 'ncc-1701'
    })
    authHeader = { Authorization: 'Bearer ' + token }
  },
  { timeout: 60000 }
)

void describe('/rest/orders/search', () => {
  void it('GET is not allowed without authentication', async () => {
    const res = await request(app).get('/rest/orders/search?q=juice')
    assert.equal(res.status, 401)
  })

  void it('GET returns line items of the logged-in user matching the query', async () => {
    const res = await request(app).get('/rest/orders/search?q=Juice').set(authHeader)
    assert.equal(res.status, 200)
    assert.equal(res.body.status, 'success')
    assert.equal(res.body.page, 1)
    assert.equal(res.body.pageSize, 10)
    assert.ok(res.body.data.length > 0)
    for (const item of res.body.data) {
      assert.equal(item.basketId, 2)
      assert.ok(item.name.includes('Juice'))
    }
  })

  void it('GET returns no items for a query without matches', async () => {
    const res = await request(app).get('/rest/orders/search?q=doesnotexist').set(authHeader)
    assert.equal(res.status, 200)
    assert.deepEqual(res.body.data, [])
    assert.equal(res.body.hasMore, false)
  })

  void it('GET treats the query as literal text', async () => {
    const res = await request(app).get('/rest/orders/search').query({ q: "zzz' OR 1=1 OR Products.name LIKE '" }).set(authHeader)
    assert.equal(res.status, 200)
    assert.deepEqual(res.body.data, [])
  })

  void it('GET caps the page size', async () => {
    const res = await request(app).get('/rest/orders/search?pageSize=500').set(authHeader)
    assert.equal(res.status, 200)
    assert.equal(res.body.pageSize, 50)
  })
})
