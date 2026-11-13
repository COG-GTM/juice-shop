/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import sinon from 'sinon'
import type { Request, Response } from 'express'
import { nftMintListener, walletNFTVerify } from '../../routes/nftMint'
const expect = chai.expect

describe('nftMint', () => {
  let res: Response
  let json: sinon.SinonSpy

  beforeEach(() => {
    json = sinon.spy()
    res = { status: sinon.stub().returns({ json }) } as unknown as Response
  })

  describe('nftMintListener', () => {
    let originalApiKey: string | undefined

    beforeEach(() => {
      originalApiKey = process.env.ALCHEMY_API_KEY
      process.env.ALCHEMY_API_KEY = 'invalid#key'
    })

    afterEach(() => {
      if (originalApiKey === undefined) {
        delete process.env.ALCHEMY_API_KEY
      } else {
        process.env.ALCHEMY_API_KEY = originalApiKey
      }
    })

    it('responds with a generic 500 message without exception details when listener setup fails', async () => {
      await nftMintListener()({} as unknown as Request, res)

      expect((res.status as sinon.SinonStub).calledWith(500)).to.equal(true)
      expect(json.calledOnceWithExactly('Unexpected error')).to.equal(true)
    })
  })

  describe('walletNFTVerify', () => {
    it('responds with a generic 500 message without exception details for malformed requests', () => {
      walletNFTVerify()({} as unknown as Request, res)

      expect((res.status as sinon.SinonStub).calledWith(500)).to.equal(true)
      expect(json.calledOnceWithExactly('Unexpected error')).to.equal(true)
    })
  })
})
