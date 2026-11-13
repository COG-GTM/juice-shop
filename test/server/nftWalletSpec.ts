/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { Mnemonic } from 'ethers'
import { getNftWalletMnemonic } from '../../lib/nftWallet'
const expect = chai.expect

describe('nftWallet', () => {
  const configuredMnemonic = process.env.NFT_WALLET_MNEMONIC

  before(() => {
    delete process.env.NFT_WALLET_MNEMONIC
  })

  after(() => {
    if (configuredMnemonic !== undefined) process.env.NFT_WALLET_MNEMONIC = configuredMnemonic
  })

  it('should generate a valid disposable 12-word mnemonic when NFT_WALLET_MNEMONIC is not set', async () => {
    const phrase = await getNftWalletMnemonic()
    expect(phrase.split(' ')).to.have.lengthOf(12)
    expect(Mnemonic.isValidMnemonic(phrase)).to.equal(true)
  })

  it('should return the same mnemonic for the lifetime of the server', async () => {
    expect(await getNftWalletMnemonic()).to.equal(await getNftWalletMnemonic())
  })
})
