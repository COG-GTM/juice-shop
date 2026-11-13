/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import sinon from 'sinon'
import net from 'node:net'
import tls from 'node:tls'
import { nftMintListener } from '../../routes/nftMint'
const expect = chai.expect

describe('nftMintListener', () => {
  let connect: sinon.SinonStub

  beforeEach(() => {
    connect = sinon.stub(tls, 'connect').callsFake(() => {
      const socket = new net.Socket()
      setImmediate(() => socket.destroy(new Error('connect ECONNREFUSED')))
      return socket as any
    })
  })

  afterEach(() => {
    connect.restore()
  })

  function res () {
    const r: any = {}
    r.status = sinon.stub().returns(r)
    r.json = sinon.stub().returns(r)
    return r
  }

  it('opens at most one blockchain connection for 100 concurrent and 100 sequential requests while the connection keeps failing', async () => {
    await Promise.all(Array.from({ length: 100 }, async () => { await nftMintListener()({} as any, res()) }))
    for (let i = 0; i < 100; i++) {
      await new Promise(resolve => setTimeout(resolve, 5))
      await nftMintListener()({} as any, res())
    }
    expect(connect.callCount).to.equal(1)
  })
})
