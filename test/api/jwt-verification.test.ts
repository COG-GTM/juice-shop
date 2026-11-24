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

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

const b64url = (obj: object) => Buffer.from(JSON.stringify(obj)).toString('base64url')
const payload = b64url({ data: { id: 1, email: 'admin@juice-sh.op', role: 'admin' }, iat: 1508639612, exp: 9999999999 })
const hs256Input = `${b64url({ alg: 'HS256', typ: 'JWT' })}.${payload}`
const forgedTokens = {
  unsigned: `${b64url({ alg: 'none', typ: 'JWT' })}.${payload}.`,
  'HS256 signed with public RSA key': `${hs256Input}.${crypto.createHmac('sha256', security.publicKey).update(hs256Input).digest('base64url')}`
}

for (const [name, token] of Object.entries(forgedTokens)) {
  void describe(`Forged ${name} token`, () => {
    void it('is rejected by GET /api/Users', async () => {
      const res = await request(app).get('/api/Users').set({ Authorization: `Bearer ${token}` })
      assert.equal(res.status, 401)
    })

    void it('is rejected by PUT /api/Users/1', async () => {
      const res = await request(app)
        .put('/api/Users/1')
        .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })
        .send({ role: 'admin' })
      assert.equal(res.status, 401)
    })

    void it('is not accepted as a session by GET /rest/user/whoami', async () => {
      const res = await request(app)
        .get('/rest/user/whoami')
        .set({ Authorization: `Bearer ${token}`, Cookie: `token=${token}` })
      assert.equal(res.status, 200)
      assert.deepEqual(res.body.user, {})
      assert.equal(security.authenticatedUsers.get(token), undefined)
    })

    void it('is rejected by GET /rest/user/change-password', async () => {
      const res = await request(app)
        .get('/rest/user/change-password?new=hacked&repeat=hacked')
        .set({ Authorization: `Bearer ${token}` })
      assert.notEqual(res.status, 200)
    })
  })
}

void describe('Server-signed token', () => {
  void it('is still rejected by denyAll() on PUT /api/Users/1', async () => {
    const res = await request(app)
      .put('/api/Users/1')
      .set({ Authorization: `Bearer ${security.authorize({ data: { id: 1, role: 'admin' } })}`, 'content-type': 'application/json' })
      .send({ role: 'admin' })
    assert.equal(res.status, 401)
  })
})
