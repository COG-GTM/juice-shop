/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import crypto from 'node:crypto'
import * as security from '../../lib/insecurity'
import { createTestApp } from './helpers/setup'

let app: Express

const b64url = (input: string | Buffer) => Buffer.from(input).toString('base64url')
const payload = b64url(JSON.stringify({ status: 'success', data: { id: 1, email: 'accountant@juice-sh.op', role: 'accounting' }, iat: Math.floor(Date.now() / 1000) }))

const unsignedHeader = b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }))
const unsignedToken = `${unsignedHeader}.${payload}.`

const hmacHeader = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
const hmacSignature = b64url(crypto.createHmac('sha256', security.publicKey).update(`${hmacHeader}.${payload}`).digest())
const hmacToken = `${hmacHeader}.${payload}.${hmacSignature}`

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

for (const [name, token] of [['unsigned (alg: none)', unsignedToken], ['HS256 signed with public RSA key', hmacToken]]) {
  void describe(`forged JWT ${name}`, () => {
    void it('is rejected by isAuthorized routes', async () => {
      const res = await request(app)
        .get('/api/Users')
        .set('Authorization', `Bearer ${token}`)

      assert.equal(res.status, 401)
    })

    void it('is rejected by denyAll routes', async () => {
      const res = await request(app)
        .get('/api/SecurityAnswers')
        .set('Authorization', `Bearer ${token}`)

      assert.equal(res.status, 401)
    })

    void it('does not create an authenticated session', async () => {
      const res = await request(app)
        .get('/rest/user/whoami')
        .set('Authorization', `Bearer ${token}`)
        .set('Cookie', `token=${token}`)

      assert.equal(res.status, 200)
      assert.equal(res.body.user.id, undefined)
      assert.equal(security.authenticatedUsers.get(token), undefined)
    })

    void it('is rejected by role checks', async () => {
      const res = await request(app)
        .get('/rest/order-history/orders')
        .set('Authorization', `Bearer ${token}`)

      assert.equal(res.status, 403)
    })
  })
}

void describe('regularly signed RS256 JWT', () => {
  void it('is accepted by isAuthorized routes', async () => {
    const res = await request(app)
      .get('/api/Users')
      .set('Authorization', `Bearer ${security.authorize({ data: { email: 'admin@juice-sh.op' } })}`)

    assert.equal(res.status, 200)
  })

  void it('is accepted by role checks', async () => {
    const res = await request(app)
      .get('/rest/order-history/orders')
      .set('Authorization', `Bearer ${security.authorize({ data: { email: 'accountant@juice-sh.op', role: 'accounting' } })}`)

    assert.equal(res.status, 200)
  })
})
