/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { checkKeys, nftUnlocked } from '../../routes/checkKeys'
import { walletNFTVerify } from '../../routes/nftMint'
import { genericErrorMessage } from '../../lib/utils'
const expect = chai.expect
chai.use(sinonChai)

describe('web3', () => {
  let res: any

  beforeEach(() => {
    res = { status: sinon.stub().returnsThis(), json: sinon.spy() }
  })

  it('walletNFTVerify should not expose exception details on failure', () => {
    walletNFTVerify()({} as any, res)

    expect(res.status).to.have.been.calledWith(500)
    expect(res.json).to.have.been.calledWith(genericErrorMessage)
  })

  it('checkKeys should not expose exception details on failure', async () => {
    await checkKeys()({} as any, res)

    expect(res.status).to.have.been.calledWith(500)
    expect(res.json).to.have.been.calledWith(genericErrorMessage)
  })

  it('nftUnlocked should not expose exception details on failure', () => {
    res.status = sinon.stub().returnsThis()
    res.status.onFirstCall().throws(new Error('internal detail'))

    nftUnlocked()({} as any, res)

    expect(res.json).to.have.been.calledOnceWith(genericErrorMessage)
  })
})
