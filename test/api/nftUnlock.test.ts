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
  delete process.env.NFT_WALLET_MNEMONIC
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('NFT wallet seed phrase', () => {
  void it('leaked in seeded feedback derives the private key accepted by /submitKey', async () => {
    const feedbacks = await request(app).get('/api/Feedbacks')
    const comment: string = feedbacks.body.data.find((f: { comment: string }) => f.comment.includes('/juicy-nft')).comment
    const phrase = /"([a-z ]+)"/.exec(comment)?.[1] ?? ''
    assert.equal(phrase.split(' ').length, 12)

    const { HDNodeWallet } = await import('ethers')
    const wallet = HDNodeWallet.fromPhrase(phrase)
    const res = await request(app)
      .post('/rest/web3/submitKey')
      .send({ privateKey: wallet.privateKey })

    assert.equal(res.status, 200)
    assert.equal(res.body.success, true)
    assert.equal(res.body.address, wallet.address)

    const status = await request(app).get('/rest/web3/nftUnlocked')
    assert.equal(status.body.status, true)
    assert.equal(status.body.address, wallet.address)
  })
})
