/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { addBounded, createContractListener } from '../../lib/contractListener'
import { contractExploitListener } from '../../routes/web3Wallet'
const expect = chai.expect
chai.use(sinonChai)

describe('contractListener', () => {
  const abi = ['event Ping(address who)']
  const address = '0x413744D59d31AFDC2889aeE602636177805Bd7b0'

  function fakeProvider () {
    const provider: any = {
      websocket: { onerror: null as any },
      destroy: sinon.stub().resolves(),
      on: sinon.stub().resolves(),
      off: sinon.stub().resolves(),
      getNetwork: sinon.stub().resolves({ chainId: 11155111n })
    }
    provider.provider = provider
    return provider
  }

  it('creates a single provider for concurrent and repeated calls', async () => {
    const provider = fakeProvider()
    const createProvider = sinon.stub().resolves(provider)
    const ensure = createContractListener({ name: 'test', address, abi, event: 'Ping', onEvent: () => {}, createProvider })

    expect(await Promise.all([ensure(), ensure(), ensure()])).to.deep.equal([true, true, true])
    expect(await ensure()).to.equal(true)

    expect(createProvider.callCount).to.equal(1)
  })

  it('destroys a failed provider and does not reconnect within the retry window', async () => {
    const first = fakeProvider()
    const second = fakeProvider()
    const createProvider = sinon.stub()
    createProvider.onFirstCall().resolves(first)
    createProvider.onSecondCall().resolves(second)
    const clock = sinon.useFakeTimers({ now: 1000000, toFake: ['Date'] })
    try {
      const ensure = createContractListener({ name: 'test', address, abi, event: 'Ping', onEvent: () => {}, createProvider, retryDelayMs: 30000 })
      expect(await ensure()).to.equal(true)

      first.websocket.onerror(new Error('boom'))
      expect(first.destroy.callCount).to.equal(1)

      for (let i = 0; i < 100; i++) expect(await ensure()).to.equal(false)
      expect(createProvider.callCount).to.equal(1)

      clock.tick(30001)
      expect(await ensure()).to.equal(true)
      expect(createProvider.callCount).to.equal(2)
    } finally {
      clock.restore()
    }
  })

  it('caps a set at the given size by evicting the oldest entry', () => {
    const set = new Set<number>()
    for (let i = 0; i < 10; i++) addBounded(set, i, 3)
    expect([...set]).to.deep.equal([7, 8, 9])
  })
})

describe('web3Wallet contractExploitListener', () => {
  let res: any

  beforeEach(() => {
    res = { status: sinon.stub().returnsThis(), json: sinon.spy() }
  })

  it('rejects a missing wallet address', async () => {
    await contractExploitListener()({ body: {} } as any, res)
    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects an oversized non-address wallet value', async () => {
    await contractExploitListener()({ body: { walletAddress: 'a'.repeat(100000) } } as any, res)
    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects a non-string wallet value', async () => {
    await contractExploitListener()({ body: { walletAddress: { $gt: '' } } } as any, res)
    expect(res.status).to.have.been.calledWith(400)
  })
})
