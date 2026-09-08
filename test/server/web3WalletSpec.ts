/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'

import { getWalletsConnected, isValidWalletAddress, rememberWallet } from '../../routes/web3Wallet'

const expect = chai.expect

describe('web3 wallet', () => {
  beforeEach(() => {
    getWalletsConnected().clear()
  })

  describe('isValidWalletAddress', () => {
    it('accepts a valid wallet address', () => {
      expect(isValidWalletAddress('0x413744D59d31AFDC2889aeE602636177805Bd7b0')).to.equal(true)
    })

    it('rejects invalid wallet addresses', () => {
      expect(isValidWalletAddress('lalalalala')).to.equal(false)
      expect(isValidWalletAddress(undefined)).to.equal(false)
      expect(isValidWalletAddress(123)).to.equal(false)
      expect(isValidWalletAddress('0x' + 'a'.repeat(39))).to.equal(false)
      expect(isValidWalletAddress('0x' + 'a'.repeat(41))).to.equal(false)
      expect(isValidWalletAddress('a'.repeat(10000))).to.equal(false)
    })
  })

  describe('rememberWallet', () => {
    it('normalizes wallet addresses to lowercase', () => {
      rememberWallet('0x413744D59d31AFDC2889aeE602636177805Bd7b0')

      expect(getWalletsConnected().has('0x413744d59d31afdc2889aee602636177805bd7b0')).to.equal(true)
      expect(getWalletsConnected().has('0x413744D59d31AFDC2889aeE602636177805Bd7b0')).to.equal(false)
    })

    it('does not grow when re-adding an existing address', () => {
      const address = '0x413744D59d31AFDC2889aeE602636177805Bd7b0'

      rememberWallet(address)
      rememberWallet(address)

      expect(getWalletsConnected()).to.have.lengthOf(1)
    })

    it('evicts the oldest wallet when the retention limit is exceeded', () => {
      for (let i = 0; i < 1500; i++) {
        rememberWallet('0x' + i.toString(16).padStart(40, '0'))
      }

      expect(getWalletsConnected()).to.have.lengthOf(1000)
      expect(getWalletsConnected().has('0x' + (0).toString(16).padStart(40, '0'))).to.equal(false)
      expect(getWalletsConnected().has('0x' + (1499).toString(16).padStart(40, '0'))).to.equal(true)
    })
  })
})
