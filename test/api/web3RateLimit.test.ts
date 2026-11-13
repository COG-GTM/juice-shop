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
  void it('POST is rejected with 429 after 20 requests within the window', async () => {
    for (let i = 0; i < 20; i++) {
      const res = await request(app)
        .post('/rest/web3/walletExploitAddress')
        .send({ walletAddress: `0x${i.toString(16).padStart(40, '0')}` })
      assert.notEqual(res.status, 429, `request ${i + 1} was rate limited`)
    }

    const limited = await request(app)
      .post('/rest/web3/walletExploitAddress')
      .send({ walletAddress: '0x0000000000000000000000000000000000000021' })
    assert.equal(limited.status, 429)
  })
})
