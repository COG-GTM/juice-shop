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
let wallet: { privateKey: string, publicKey: string, address: string }

const skipReason = process.env.ALCHEMY_API_KEY ? undefined : 'ALCHEMY_API_KEY not set'

before(async () => {
  if (!process.env.ALCHEMY_API_KEY) return
  const { HDNodeWallet, Mnemonic, randomBytes } = await import('ethers')
  process.env.NFT_WALLET_MNEMONIC = Mnemonic.fromEntropy(randomBytes(16)).phrase
  wallet = HDNodeWallet.fromPhrase(process.env.NFT_WALLET_MNEMONIC)
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/submitKey', { skip: skipReason }, () => {
  void it('POST missing key in request body gets rejected as non-Ethereum key', async () => {
    const res = await request(app)
      .post('/rest/web3/submitKey')
      .send({})

    assert.equal(res.status, 401)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.success, false)
    assert.equal(res.body.message, 'Looks like you entered a non-Ethereum private key to access me.')
  })

  void it('POST arbitrary string in request body gets rejected as non-Ethereum key', async () => {
    const res = await request(app)
      .post('/rest/web3/submitKey')
      .send({ privateKey: 'lalalala' })

    assert.equal(res.status, 401)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.success, false)
    assert.equal(res.body.message, 'Looks like you entered a non-Ethereum private key to access me.')
  })

  void it('POST public wallet key in request body gets rejected as such', async () => {
    const res = await request(app)
      .post('/rest/web3/submitKey')
      .send({ privateKey: wallet.publicKey })

    assert.equal(res.status, 401)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.success, false)
    assert.equal(res.body.message, 'Looks like you entered the public key of my ethereum wallet!')
  })

  void it('POST wallet address in request body gets rejected as such', async () => {
    const res = await request(app)
      .post('/rest/web3/submitKey')
      .send({ privateKey: wallet.address })

    assert.equal(res.status, 401)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.success, false)
    assert.equal(res.body.message, 'Looks like you entered the public address of my ethereum wallet!')
  })

  void it('POST private key in request body gets accepted', async () => {
    const res = await request(app)
      .post('/rest/web3/submitKey')
      .send({ privateKey: wallet.privateKey })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.success, true)
    assert.equal(res.body.message, 'Challenge successfully solved')
  })
})

void describe('/nftUnlocked', { skip: skipReason }, () => {
  void it('GET solution status of "Unlock NFT" challenge', async () => {
    const res = await request(app)
      .get('/rest/web3/nftUnlocked')

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.status, 'boolean')
    assert.equal(res.body.address, wallet.address)
  })
})

void describe('/nftMintListen', { skip: skipReason }, () => {
  void it('GET call confirms registration of event listener', async () => {
    const res = await request(app)
      .get('/rest/web3/nftMintListen')

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.success, true)
    assert.equal(res.body.message, 'Event Listener Created')
  })
})

void describe('/walletNFTVerify', { skip: skipReason }, () => {
  void it('POST missing wallet address fails to solve minting challenge', async () => {
    const res = await request(app)
      .post('/rest/web3/walletNFTVerify')
      .send({})

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.success, false)
    assert.equal(res.body.message, 'Wallet did not mint the NFT')
  })

  void it('POST invalid wallet address fails to solve minting challenge', async () => {
    const res = await request(app)
      .post('/rest/web3/walletNFTVerify')
      .send({ walletAddress: 'lalalalala' })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.success, false)
    assert.equal(res.body.message, 'Wallet did not mint the NFT')
  })
})

void describe('/walletExploitAddress', { skip: skipReason }, () => {
  void it('POST missing wallet address in request body still leads to success notification', async () => {
    const res = await request(app)
      .post('/rest/web3/walletExploitAddress')
      .send({})

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.success, true)
    assert.equal(res.body.message, 'Event Listener Created')
  })

  void it('POST invalid wallet address in request body still leads to success notification', async () => {
    const res = await request(app)
      .post('/rest/web3/walletExploitAddress')
      .send({ walletAddress: 'lalalalala' })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.success, true)
    assert.equal(res.body.message, 'Event Listener Created')
  })

  void it('POST self-referential address in request body leads to success notification', async () => {
    const res = await request(app)
      .post('/rest/web3/walletExploitAddress')
      .send({ walletAddress: '0x413744D59d31AFDC2889aeE602636177805Bd7b0' })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.success, true)
    assert.equal(res.body.message, 'Event Listener Created')
  })
})
