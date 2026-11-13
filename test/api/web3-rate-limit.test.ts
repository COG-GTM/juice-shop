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

const walletAddress = '0x0000000000000000000000000000000000000000'

void describe('/rest/web3 rate limiting', () => {
  before(async () => {
    for (let i = 0; i < 100; i++) {
      const res = await request(app)
        .post('/rest/web3/walletNFTVerify')
        .send({ walletAddress })
      assert.equal(res.status, 200)
      assert.equal(res.body.success, false)
    }
  }, { timeout: 60000 })

  void it('POST /walletNFTVerify is rejected with 429 after 100 requests', async () => {
    const res = await request(app)
      .post('/rest/web3/walletNFTVerify')
      .send({ walletAddress })
    assert.equal(res.status, 429)
  })

  void it('rotating X-Forwarded-For does not reset the limit', async () => {
    const res = await request(app)
      .post('/rest/web3/walletNFTVerify')
      .set('X-Forwarded-For', '203.0.113.42')
      .send({ walletAddress })
    assert.equal(res.status, 429)
  })

  void it('GET /nftMintListen is rejected with 429 after the limit, even with a new X-Forwarded-For', async () => {
    const res = await request(app)
      .get('/rest/web3/nftMintListen')
      .set('X-Forwarded-For', '198.51.100.7')
    assert.equal(res.status, 429)
  })

  void it('limit is shared across all /rest/web3 endpoints', async () => {
    const probes: Array<[string, () => request.Test]> = [
      ['POST /rest/web3/submitKey', () => request(app).post('/rest/web3/submitKey').send({ privateKey: '0x0' })],
      ['GET /rest/web3/nftUnlocked', () => request(app).get('/rest/web3/nftUnlocked')],
      ['GET /rest/web3/nftMintListen', () => request(app).get('/rest/web3/nftMintListen')],
      ['POST /rest/web3/walletExploitAddress', () => request(app).post('/rest/web3/walletExploitAddress').send({ walletAddress })]
    ]
    for (const [route, probe] of probes) {
      const res = await probe()
      assert.equal(res.status, 429, route)
    }
  })

  void it('endpoints outside /rest/web3 are not affected', async () => {
    const res = await request(app)
      .get('/rest/languages')
    assert.equal(res.status, 200)
  })
})
