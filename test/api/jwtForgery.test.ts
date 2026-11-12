/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import request from 'supertest'
import jwt from 'jsonwebtoken'
import type { Express } from 'express'
import * as security from '../../lib/insecurity'
import { createTestApp } from './helpers/setup'

let app: Express

const adminPayload = { status: 'success', data: { id: 1, email: 'admin@juice-sh.op', role: 'admin' } }

const base64url = (input: object) => Buffer.from(JSON.stringify(input)).toString('base64url')

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('JWT signature verification', () => {
  void it('accepts a token issued by the server', async () => {
    const res = await request(app).get('/api/Users').set('Authorization', 'Bearer ' + security.authorize(adminPayload))
    assert.equal(res.status, 200)
  })

  void it('rejects an RS256 token signed with a foreign private key', async () => {
    const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
    const token = jwt.sign(adminPayload, privateKey, { algorithm: 'RS256', expiresIn: '6h' })
    const res = await request(app).get('/api/Users').set('Authorization', 'Bearer ' + token)
    assert.equal(res.status, 401)
    assert.equal(security.verify(token), false)
  })

  void it('rejects an unsigned token with alg "none"', async () => {
    const token = `${base64url({ alg: 'none', typ: 'JWT' })}.${base64url(adminPayload)}.`
    const res = await request(app).get('/api/Users').set('Authorization', 'Bearer ' + token)
    assert.equal(res.status, 401)
    assert.equal(security.verify(token), false)
  })

  void it('rejects an HS256 token HMAC-signed with the public RSA key', async () => {
    const unsigned = `${base64url({ alg: 'HS256', typ: 'JWT' })}.${base64url(adminPayload)}`
    const signature = crypto.createHmac('sha256', security.publicKey).update(unsigned).digest('base64url')
    const token = `${unsigned}.${signature}`
    const res = await request(app).get('/api/Users').set('Authorization', 'Bearer ' + token)
    assert.equal(res.status, 401)
    assert.equal(security.verify(token), false)
  })
})
