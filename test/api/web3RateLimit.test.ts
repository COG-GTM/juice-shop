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

void describe('/rest/web3 rate limiting', () => {
  void it('blocks requests to all Web3 endpoints after 100 requests per client, regardless of X-Forwarded-For', async () => {
    for (let i = 0; i < 100; i++) {
      const res = await request(app)
        .get('/rest/web3/nftUnlocked')
        .set('X-Forwarded-For', `10.0.${Math.floor(i / 256)}.${i % 256}`)
      assert.equal(res.status, 200)
      assert.equal(res.headers['x-ratelimit-remaining'], String(99 - i))
    }

    const blocked = await request(app)
      .get('/rest/web3/nftUnlocked')
      .set('X-Forwarded-For', '192.168.99.99')
    assert.equal(blocked.status, 429)

    const blockedMintListen = await request(app).get('/rest/web3/nftMintListen')
    assert.equal(blockedMintListen.status, 429)

    const blockedVerify = await request(app)
      .post('/rest/web3/walletNFTVerify')
      .send({ walletAddress: 'lalalalala' })
    assert.equal(blockedVerify.status, 429)

    const blockedSubmitKey = await request(app)
      .post('/rest/web3/submitKey')
      .send({ privateKey: 'lalalala' })
    assert.equal(blockedSubmitKey.status, 429)

    const blockedExploit = await request(app)
      .post('/rest/web3/walletExploitAddress')
      .send({ walletAddress: 'lalalalala' })
    assert.equal(blockedExploit.status, 429)

    const otherRoute = await request(app).get('/rest/languages')
    assert.equal(otherRoute.status, 200)
  })
})
