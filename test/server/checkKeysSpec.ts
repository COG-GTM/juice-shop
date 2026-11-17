/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { HDNodeWallet } from 'ethers'
import { checkKeys } from '../../routes/checkKeys'
import { challenges } from '../../data/datacache'
import { type ChallengeModel } from '../../models/challenge'
const expect = chai.expect
chai.use(sinonChai)

describe('checkKeys', () => {
  const originalMnemonic = process.env.NFT_WALLET_MNEMONIC
  const originalChallenge = challenges.nftUnlockChallenge
  const wallet = HDNodeWallet.createRandom()
  let req: any
  let res: any

  beforeEach(() => {
    process.env.NFT_WALLET_MNEMONIC = wallet.mnemonic?.phrase
    challenges.nftUnlockChallenge = { solved: true } as unknown as ChallengeModel
    req = { body: {} }
    res = { json: sinon.spy() }
    res.status = sinon.stub().returns(res)
  })

  afterEach(() => {
    if (originalChallenge === undefined) {
      delete (challenges as Partial<typeof challenges>).nftUnlockChallenge
    } else {
      challenges.nftUnlockChallenge = originalChallenge
    }
    if (originalMnemonic === undefined) {
      delete process.env.NFT_WALLET_MNEMONIC
    } else {
      process.env.NFT_WALLET_MNEMONIC = originalMnemonic
    }
  })

  it('should reject every key when no wallet mnemonic is configured', async () => {
    delete process.env.NFT_WALLET_MNEMONIC
    req.body.privateKey = wallet.privateKey

    await checkKeys()(req, res)

    expect(res.status).to.have.been.calledWith(503)
    expect(res.json).to.have.been.calledWith(sinon.match({ success: false }))
  })

  it('should accept the private key of the configured wallet', async () => {
    req.body.privateKey = wallet.privateKey

    await checkKeys()(req, res)

    expect(res.status).to.have.been.calledWith(200)
    expect(res.json).to.have.been.calledWith(sinon.match({ success: true }))
  })

  it('should no longer accept the private key derived from the formerly hardcoded seed phrase', async () => {
    req.body.privateKey = '0x5bcc3e9d38baa06e7bfaab80ae5957bbe8ef059e640311d7d6d465e6bc948e3e'

    await checkKeys()(req, res)

    expect(res.status).to.have.been.calledWith(401)
    expect(res.json).to.have.been.calledWith(sinon.match({ success: false }))
  })

  it('should recognize the public address of the configured wallet', async () => {
    req.body.privateKey = wallet.address

    await checkKeys()(req, res)

    expect(res.status).to.have.been.calledWith(401)
    expect(res.json).to.have.been.calledWith(sinon.match({ message: 'Looks like you entered the public address of my ethereum wallet!' }))
  })
})
