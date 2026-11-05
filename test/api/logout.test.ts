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

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

const jsonHeader = { 'content-type': 'application/json' }
const logoutPw = 'logout-pass'
const staleUserPw = 'before-change'

void describe('/rest/user/logout', () => {
  void it('POST logout revokes the presented token for map-backed routes', async () => {
    await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({ email: 'logout@be.rt', password: logoutPw })
      .expect(201)

    const { token } = await login(app, { email: 'logout@be.rt', password: logoutPw })
    await new Promise(resolve => setTimeout(resolve, 1100))
    const { token: otherDevice } = await login(app, { email: 'logout@be.rt', password: logoutPw })

    await request(app)
      .get('/rest/order-history')
      .set({ Authorization: 'Bearer ' + token })
      .expect(200)

    await request(app)
      .post('/rest/user/logout')
      .set({ Authorization: 'Bearer ' + token })
      .expect(204)

    await request(app)
      .get('/rest/order-history')
      .set({ Authorization: 'Bearer ' + token })
      .expect(401)
    await request(app)
      .post('/rest/user/data-export')
      .set({ ...jsonHeader, Authorization: 'Bearer ' + token })
      .send({ format: 1 })
      .expect(401)
    await request(app)
      .get('/rest/user/whoami')
      .set({ Authorization: 'Bearer ' + token, Cookie: 'token=' + token })
      .expect(200)
      .expect(res => { assert.deepEqual(res.body.user, {}) })
    await request(app)
      .get('/rest/2fa/status')
      .set({ Authorization: 'Bearer ' + token })
      .expect(401)

    await request(app)
      .get('/rest/order-history')
      .set({ Authorization: 'Bearer ' + otherDevice })
      .expect(200)
  })

  void it('POST logout without a valid token is rejected', async () => {
    await request(app)
      .post('/rest/user/logout')
      .expect(401)
    await request(app)
      .post('/rest/user/logout')
      .set({ Authorization: 'Bearer not.a.token' })
      .expect(401)
  })
})

void describe('session invalidation after password change', () => {
  void it('a token issued before the password change is rejected on data export', async () => {
    await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({ email: 'stale@to.ken', password: staleUserPw })
      .expect(201)

    const { token: stolenToken } = await login(app, { email: 'stale@to.ken', password: staleUserPw })
    await new Promise(resolve => setTimeout(resolve, 1100))
    const { token: ownerToken } = await login(app, { email: 'stale@to.ken', password: staleUserPw })

    await request(app)
      .post('/rest/user/change-password')
      .set({ ...jsonHeader, Authorization: 'Bearer ' + ownerToken })
      .send({ current: staleUserPw, new: 'after-change', repeat: 'after-change' })
      .expect(200)

    await request(app)
      .post('/rest/user/data-export')
      .set({ ...jsonHeader, Authorization: 'Bearer ' + stolenToken })
      .send({ format: 1 })
      .expect(401)
    await request(app)
      .get('/rest/order-history')
      .set({ Authorization: 'Bearer ' + stolenToken })
      .expect(401)
  })
})
