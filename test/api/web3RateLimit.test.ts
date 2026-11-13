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

void describe('/rest/web3/walletNFTVerify', () => {
  void it('POST is rate limited after 100 requests per window', async () => {
    for (let i = 0; i < 100; i++) {
      const res = await request(app)
        .post('/rest/web3/walletNFTVerify')
        .send({ walletAddress: `0x${i.toString(16).padStart(40, '0')}` })
      assert.equal(res.status, 200)
      assert.equal(res.body.success, false)
    }

    const res = await request(app)
      .post('/rest/web3/walletNFTVerify')
      .send({ walletAddress: '0x8343d2eb2B13A2495De435a1b15e85b98115Ce05' })
    assert.equal(res.status, 429)
  })
})
