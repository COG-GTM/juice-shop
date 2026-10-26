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

const jsonHeader = { 'content-type': 'application/json' }
let app: Express
let authHeader: { Authorization: string, 'content-type': string }

const endpoints: Array<[string, object]> = [
  ['/api/Users/1', { email: 'mallory@evil.test', password: 'mallory' }],
  ['/api/Cards/1', { fullName: 'Mallory', cardNum: 4111111111111111 }],
  ['/api/Addresss/1', { fullName: 'Mallory' }],
  ['/api/Recycles/1', { quantity: 1000 }],
  ['/api/Hints/1', { unlocked: true }],
  ['/api/Feedbacks/1', { comment: 'Mallory was here', rating: 1 }],
  ['/api/BasketItems/1', { quantity: 1000 }],
  ['/api/Products/1', { description: 'Mallory was here' }],
  ['/api/Quantitys/1', { quantity: 0 }]
]

before(
  async () => {
    const result = await createTestApp()
    app = result.app

    const { token } = await login(app, {
      email: 'jim@juice-sh.op',
      password: 'ncc-1701'
    })
    authHeader = {
      Authorization: 'Bearer ' + token,
      'content-type': 'application/json'
    }
  },
  { timeout: 60000 }
)

void describe('PATCH on generated /api endpoints', () => {
  for (const [path, body] of endpoints) {
    void it(`PATCH ${path} is forbidden via public API`, async () => {
      const res = await request(app).patch(path).set(jsonHeader).send(body)
      assert.equal(res.status, 401)
    })

    void it(`PATCH ${path} is forbidden via API even when authenticated`, async () => {
      const res = await request(app).patch(path).set(authHeader).send(body)
      assert.equal(res.status, 401)
    })
  }

  void it('PATCH does not change the admin account', async () => {
    await request(app).patch('/api/Users/1').set(jsonHeader).send({ password: 'mallory' })
    const res = await request(app)
      .post('/rest/user/login')
      .set(jsonHeader)
      .send({ email: 'admin@juice-sh.op', password: 'mallory' })
    assert.equal(res.status, 401)
  })
})
