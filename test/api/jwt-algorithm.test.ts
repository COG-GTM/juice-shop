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

const forge = (alg: string, data: Record<string, unknown>, sign: (input: string) => string) => {
  const header = Buffer.from(JSON.stringify({ alg, typ: 'JWT' })).toString('base64url')
  const payload = Buffer.from(JSON.stringify({ data })).toString('base64url')
  return `${header}.${payload}.${sign(`${header}.${payload}`)}`
}
const unsigned = (data: Record<string, unknown>) => forge('none', data, () => '')
const hs256WithPublicKey = (data: Record<string, unknown>) => forge('HS256', data, (input) => crypto.createHmac('sha256', security.publicKey).update(input).digest('base64url'))
const bearer = (token: string) => ({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })

const accountant = { id: 15, email: 'accountant@juice-sh.op', role: 'accounting' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('isAuthorized middleware', () => {
  void it('accepts an RS256 token issued by the server', async () => {
    const res = await request(app).get('/api/Complaints').set(bearer(security.authorize({ data: accountant })))
    assert.equal(res.status, 200)
  })

  void it('rejects an unsigned alg:none token', async () => {
    const res = await request(app).get('/api/Complaints').set(bearer(unsigned(accountant)))
    assert.equal(res.status, 401)
  })

  void it('rejects an HS256 token signed with the public RSA key', async () => {
    const res = await request(app).get('/api/Complaints').set(bearer(hs256WithPublicKey(accountant)))
    assert.equal(res.status, 401)
  })
})

void describe('GET /api/Users', () => {
  const admin = { id: 1, email: 'admin@juice-sh.op', role: 'admin' }

  void it('rejects an unsigned alg:none admin token', async () => {
    const res = await request(app).get('/api/Users').set(bearer(unsigned(admin)))
    assert.equal(res.status, 401)
  })

  void it('rejects an HS256 admin token signed with encryptionkeys/jwt.pub', async () => {
    const res = await request(app).get('/api/Users').set(bearer(hs256WithPublicKey(admin)))
    assert.equal(res.status, 401)
  })

  void it('accepts a real RS256 login token', async () => {
    const res = await request(app).get('/api/Users').set(bearer(security.authorize({ data: admin })))
    assert.equal(res.status, 200)
  })
})

void describe('denyAll middleware', () => {
  void it('rejects even an RS256 token issued by the server', async () => {
    const res = await request(app).get('/api/Complaints/1').set(bearer(security.authorize({ data: accountant })))
    assert.equal(res.status, 401)
  })

  void it('rejects an unsigned alg:none token', async () => {
    const res = await request(app).get('/api/Complaints/1').set(bearer(unsigned(accountant)))
    assert.equal(res.status, 401)
  })

  void it('rejects requests without a token', async () => {
    const res = await request(app).get('/api/Complaints/1')
    assert.equal(res.status, 401)
  })
})

void describe('isAccounting middleware', () => {
  void it('accepts an RS256 token with accounting role', async () => {
    const res = await request(app).get('/rest/order-history/orders').set(bearer(security.authorize({ data: accountant })))
    assert.equal(res.status, 200)
  })

  void it('rejects an alg:none token claiming accounting role', async () => {
    const res = await request(app).get('/rest/order-history/orders').set(bearer(unsigned(accountant)))
    assert.equal(res.status, 403)
  })

  void it('rejects an HS256/public-key token claiming accounting role', async () => {
    const res = await request(app).get('/rest/order-history/orders').set(bearer(hs256WithPublicKey(accountant)))
    assert.equal(res.status, 403)
  })
})

void describe('updateAuthenticatedUsers middleware', () => {
  const admin = { id: 1, email: 'admin@juice-sh.op', role: 'admin' }

  void it('does not create a session for an alg:none token sent to /rest/user/whoami', async () => {
    const token = unsigned(admin)
    const res = await request(app).get('/rest/user/whoami').set('Cookie', 'token=' + token)
    assert.equal(res.status, 200)
    assert.equal(res.body.user.id, undefined)
    assert.equal(security.authenticatedUsers.get(token), undefined)
  })

  void it('does not create a session for an HS256/public-key token sent to /rest/user/whoami', async () => {
    const token = hs256WithPublicKey(admin)
    const res = await request(app).get('/rest/user/whoami').set('Cookie', 'token=' + token)
    assert.equal(res.status, 200)
    assert.equal(res.body.user.id, undefined)
    assert.equal(security.authenticatedUsers.get(token), undefined)
  })
})

void describe('forged token password change', () => {
  const admin = { id: 1, email: 'admin@juice-sh.op', role: 'admin' }

  for (const [name, forgeToken] of [['alg:none', unsigned], ['HS256/public-key', hs256WithPublicKey]] as const) {
    void it(`rejects a ${name} admin token replayed via /rest/user/whoami and leaves the admin password unchanged`, async () => {
      const token = forgeToken(admin)
      await request(app).get('/rest/user/whoami').set('Cookie', 'token=' + token)

      const res = await request(app)
        .post('/rest/user/change-password')
        .set(bearer(token))
        .send({ new: 'pwned', repeat: 'pwned' })
      assert.equal(res.status, 500)
      assert.ok(res.text.includes('Error: Blocked illegal activity'))

      const original = await request(app).post('/rest/user/login').set('content-type', 'application/json').send({ email: admin.email, password: 'admin123' })
      assert.equal(original.status, 200)
      const hijacked = await request(app).post('/rest/user/login').set('content-type', 'application/json').send({ email: admin.email, password: 'pwned' })
      assert.equal(hijacked.status, 401)
    })
  }
})
