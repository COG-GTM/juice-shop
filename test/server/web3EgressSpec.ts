/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { nftMintListener } from '../../routes/nftMint'
import { contractExploitListener } from '../../routes/web3Wallet'

const expect = chai.expect
chai.use(sinonChai)

describe('web3 third-party egress', () => {
  let req: any
  let res: any
  let json: any
  let originalApiKey: string | undefined

  beforeEach(() => {
    originalApiKey = process.env.ALCHEMY_API_KEY
    delete process.env.ALCHEMY_API_KEY
    json = sinon.spy()
    res = { status: sinon.stub().returns({ json }) }
    req = { body: { walletAddress: '0x0000000000000000000000000000000000000000' } }
  })

  afterEach(() => {
    if (originalApiKey === undefined) {
      delete process.env.ALCHEMY_API_KEY
    } else {
      process.env.ALCHEMY_API_KEY = originalApiKey
    }
  })

  it('nftMintListener refuses to connect without a configured API key', async () => {
    await nftMintListener()(req, res)

    expect(res.status).to.have.been.calledWith(503)
    expect(json).to.have.been.calledWith(sinon.match({ success: false }))
  })

  it('contractExploitListener refuses to connect without a configured API key', async () => {
    await contractExploitListener()(req, res)

    expect(res.status).to.have.been.calledWith(503)
    expect(json).to.have.been.calledWith(sinon.match({ success: false }))
  })
})
