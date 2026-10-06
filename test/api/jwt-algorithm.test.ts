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

void describe('denyAll middleware', () => {
  void it('rejects even an RS256 token issued by the server', async () => {
    const res = await request(app).get('/api/Complaints/1').set(bearer(security.authorize({ data: accountant })))
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
