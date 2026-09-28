/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

let app: Express
let collidingUserToken: string

before(async () => {
  const result = await createTestApp()
  app = result.app
  const collidingEmail = 'odmen@' + config.get<string>('application.domain')
  await register(app, { email: collidingEmail, password: 'collision123' })
  const { token } = await login(app, { email: collidingEmail, password: 'collision123' })
  collidingUserToken = token
}, { timeout: 60000 })

void describe('orders of users with colliding vowel-masked emails', () => {
  void it('GET /rest/order-history does not return orders of another user', async () => {
    const res = await request(app)
      .get('/rest/order-history')
      .set({ Authorization: 'Bearer ' + collidingUserToken, 'content-type': 'application/json' })

    assert.equal(res.status, 200)
    assert.deepEqual(res.body.data, [])
  })

  void it('POST /rest/user/data-export does not include orders of another user', async () => {
    const res = await request(app)
      .post('/rest/user/data-export')
      .set({ Authorization: 'Bearer ' + collidingUserToken, 'content-type': 'application/json' })
      .send({ format: '1' })

    assert.equal(res.status, 200)
    assert.deepEqual(JSON.parse(res.body.userData).orders, [])
  })
})
