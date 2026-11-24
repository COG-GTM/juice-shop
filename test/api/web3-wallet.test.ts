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
let authHeader: { Authorization: string, 'content-type': string }

before(async () => {
  const result = await createTestApp()
  app = result.app

  const { token } = await login(app, {
    email: 'jim@juice-sh.op',
    password: 'ncc-1701'
  })
  authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}, { timeout: 60000 })

void describe('/rest/web3/walletExploitAddress', () => {
  void it('POST without authentication is rejected', async () => {
    const res = await request(app)
      .post('/rest/web3/walletExploitAddress')
      .send({ walletAddress: '0x413744D59d31AFDC2889aeE602636177805Bd7b0' })

    assert.equal(res.status, 401)
  })

  void it('POST with a non-address walletAddress is rejected', async () => {
    const res = await request(app)
      .post('/rest/web3/walletExploitAddress')
      .set(authHeader)
      .send({ walletAddress: 'x'.repeat(50000) })

    assert.equal(res.status, 400)
    assert.equal(res.body.success, false)
  })

  void it('POST with an object walletAddress is rejected', async () => {
    const res = await request(app)
      .post('/rest/web3/walletExploitAddress')
      .set(authHeader)
      .send({ walletAddress: { $gt: '' } })

    assert.equal(res.status, 400)
  })
})
