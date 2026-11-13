/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { contractExploitListener } from '../../routes/web3Wallet'
import { nftMintListener, walletNFTVerify } from '../../routes/nftMint'
import { checkKeys, nftUnlocked } from '../../routes/checkKeys'
const expect = chai.expect
chai.use(sinonChai)

describe('web3 error responses', () => {
  let res: any

  beforeEach(() => {
    res = { status: sinon.stub(), json: sinon.spy() }
    res.status.returns(res)
    res.status.withArgs(200).throws(new Error('internal detail\n    at Object.<anonymous> (/juice-shop/routes/web3Wallet.ts:34:11)'))
  })

  const expectGenericError = () => {
    expect(res.status).to.have.been.calledWith(500)
    expect(res.json).to.have.been.calledOnceWith('Internal Server Error')
  }

  it('contractExploitListener does not expose error details', async () => {
    await contractExploitListener()({ body: { walletAddress: '0x0' } } as any, res)
    expectGenericError()
  })

  it('nftMintListener does not expose error details', async () => {
    await nftMintListener()({} as any, res)
    expectGenericError()
  })

  it('walletNFTVerify does not expose error details', () => {
    walletNFTVerify()({} as any, res)
    expectGenericError()
  })

  it('checkKeys does not expose error details', async () => {
    await checkKeys()({} as any, res)
    expectGenericError()
  })

  it('nftUnlocked does not expose error details', () => {
    nftUnlocked()({} as any, res)
    expectGenericError()
  })
})
