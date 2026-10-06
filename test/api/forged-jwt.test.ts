/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import * as security from '../../lib/insecurity'

let app: Express

const base64url = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url')
const payload = { data: { id: 1, email: 'admin@juice-sh.op', role: 'accounting' }, iat: 1508639612, exp: 9999999999 }

const unsignedToken = `${base64url({ alg: 'none', typ: 'JWT' })}.${base64url(payload)}.`
const hs256Input = `${base64url({ alg: 'HS256', typ: 'JWT' })}.${base64url(payload)}`
const hs256Token = `${hs256Input}.${crypto.createHmac('sha256', security.publicKey).update(hs256Input).digest('base64url')}`

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

for (const [name, token] of [['alg "none"', unsignedToken], ['HS256 signed with the public RSA key', hs256Token]]) {
  void describe(`forged JWT with ${name}`, () => {
    void it('is rejected by isAuthorized()', async () => {
      const res = await request(app).get('/api/Complaints').set({ Authorization: `Bearer ${token}` })
      assert.equal(res.status, 401)
    })

    void it('is rejected by isAccounting()', async () => {
      const res = await request(app).get('/rest/order-history/orders').set({ Authorization: `Bearer ${token}` })
      assert.equal(res.status, 403)
    })

    void it('is not registered as an authenticated user by updateAuthenticatedUsers()', async () => {
      const res = await request(app).get('/rest/user/whoami').set('Cookie', `token=${token}`)
      assert.equal(res.status, 200)
      assert.equal(res.body.user.email, undefined)
      assert.equal(security.authenticatedUsers.get(token), undefined)
    })
  })
}

void describe('regular RS256 JWT', () => {
  void it('is accepted by isAuthorized()', async () => {
    const token = security.authorize({ data: { id: 1, email: 'admin@juice-sh.op' } })
    const res = await request(app).get('/api/Complaints').set({ Authorization: `Bearer ${token}` })
    assert.equal(res.status, 200)
  })

  void it('is accepted by isAccounting()', async () => {
    const token = security.authorize({ data: { id: 1, email: 'accountant@juice-sh.op', role: 'accounting' } })
    const res = await request(app).get('/rest/order-history/orders').set({ Authorization: `Bearer ${token}` })
    assert.equal(res.status, 200)
  })
})
