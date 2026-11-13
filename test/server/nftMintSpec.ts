/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { walletNFTVerify } from '../../routes/nftMint'
import { checkKeys } from '../../routes/checkKeys'
import * as utils from '../../lib/utils'
const expect = chai.expect
chai.use(sinonChai)

describe('nftMint', () => {
  let req: any
  let res: any

  beforeEach(() => {
    const error = new Error('SQLITE_ERROR: no such table: Wallets')
    error.stack = 'Error: SQLITE_ERROR: no such table: Wallets\n    at /juice-shop/build/routes/nftMint.js:42:13'
    req = {}
    Object.defineProperty(req, 'body', { get: () => { throw error } })
    res = { json: sinon.spy() }
    res.status = sinon.stub().returns(res)
  })

  it('walletNFTVerify responds with a generic message instead of exception details', () => {
    walletNFTVerify()(req, res)

    expect(res.status).to.have.been.calledWith(500)
    expect(res.json).to.have.been.calledOnceWithExactly(utils.unexpectedErrorMessage)
  })

  it('checkKeys responds with a generic message instead of exception details', async () => {
    await checkKeys()(req, res)

    expect(res.status).to.have.been.calledWith(500)
    expect(res.json).to.have.been.calledOnceWithExactly(utils.unexpectedErrorMessage)
  })
})
