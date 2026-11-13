/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/web3/walletExploitAddress rate limiting', () => {
  void it('POST is throttled with 429 after 100 requests within the window', async () => {
    for (let i = 0; i < 100; i++) {
      const res = await request(app)
        .post('/rest/web3/walletExploitAddress')
        .send({ walletAddress: '0x413744D59d31AFDC2889aeE602636177805Bd7b0' })
      assert.notEqual(res.status, 429, `request ${i + 1} was throttled too early`)
    }

    const res = await request(app)
      .post('/rest/web3/walletExploitAddress')
      .send({ walletAddress: '0x413744D59d31AFDC2889aeE602636177805Bd7b0' })

    assert.equal(res.status, 429)
  })
})
