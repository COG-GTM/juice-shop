/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { contractExploitListener, registerWalletAddress, isWalletAddressConnected, connectedWalletsCount, maxWalletsConnected } from '../../routes/web3Wallet'

const expect = chai.expect
chai.use(sinonChai)

const toAddress = (n: number) => '0x' + n.toString(16).padStart(40, '0')

describe('web3Wallet', () => {
  describe('contractExploitListener', () => {
    let res: any

    beforeEach(() => {
      res = { status: sinon.stub().returnsThis(), json: sinon.spy() }
    })

    for (const walletAddress of [undefined, '', 'lalalalala', '0x' + 'a'.repeat(39), '0x' + 'g'.repeat(40), 'A'.repeat(50000), { toLowerCase: '' }, ['0x413744D59d31AFDC2889aeE602636177805Bd7b0']]) {
      it(`rejects invalid wallet address ${JSON.stringify(walletAddress)?.substring(0, 50)} without storing it`, async () => {
        const before = connectedWalletsCount()

        await contractExploitListener()({ body: { walletAddress } } as any, res)

        expect(res.status).to.have.been.calledWith(400)
        expect(res.json).to.have.been.calledWith({ success: false, message: 'Invalid wallet address' })
        expect(connectedWalletsCount()).to.equal(before)
      })
    }
  })

  describe('registerWalletAddress', () => {
    it('accepts a 0x-prefixed 40-hex address and matches it case-insensitively', () => {
      expect(registerWalletAddress('0x413744D59d31AFDC2889aeE602636177805Bd7b0')).to.equal(true)
      expect(isWalletAddressConnected('0x413744d59d31afdc2889aee602636177805bd7b0')).to.equal(true)
    })

    it('does not grow when the same address is registered repeatedly', () => {
      registerWalletAddress(toAddress(1))
      const before = connectedWalletsCount()
      registerWalletAddress(toAddress(1).toUpperCase().replace('0X', '0x'))
      expect(connectedWalletsCount()).to.equal(before)
    })

    it(`caps the connected wallets at ${maxWalletsConnected} by evicting the oldest`, () => {
      for (let i = 0; i < maxWalletsConnected * 5; i++) {
        registerWalletAddress(toAddress(i + 100))
      }
      expect(connectedWalletsCount()).to.equal(maxWalletsConnected)
      expect(isWalletAddressConnected(toAddress(100))).to.equal(false)
      expect(isWalletAddressConnected(toAddress(maxWalletsConnected * 5 + 99))).to.equal(true)
    })
  })
})
