/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import {
  contractExploitListener,
  consumeWallet,
  exploitListenerDeps,
  isWalletAddress,
  MAX_WALLETS_CONNECTED,
  rememberWallet,
  stopExploitListener,
  WALLET_TTL_MS,
  walletsConnected
} from '../../routes/web3Wallet'
const expect = chai.expect
chai.use(sinonChai)

const address = (n: number) => '0x' + n.toString(16).padStart(40, '0')
const nextTick = async () => { await new Promise((resolve) => setImmediate(resolve)) }

function fakeEthers ({ failSubscription = false } = {}) {
  const providers: any[] = []
  const handlers: Array<(exploiter: string) => void> = []
  class WebSocketProvider {
    websocket: any = { onerror: null }
    destroy = sinon.spy()
    constructor () { providers.push(this) }
  }
  class Contract {
    async on (_event: string, handler: (exploiter: string) => void) {
      await nextTick()
      if (failSubscription) throw new Error('subscription failed')
      handlers.push(handler)
    }
  }
  return { ethers: { WebSocketProvider, Contract } as any, providers, handlers }
}

function mockRes () {
  const res: any = { status: sinon.stub(), json: sinon.spy() }
  res.status.returns(res)
  return res
}

describe('web3Wallet', () => {
  let res: any

  beforeEach(() => {
    walletsConnected.clear()
    res = mockRes()
  })

  afterEach(() => {
    stopExploitListener()
    sinon.restore()
  })

  it('accepts only 0x-prefixed 40-hex wallet addresses', () => {
    expect(isWalletAddress('0x413744D59d31AFDC2889aeE602636177805Bd7b0')).to.equal(true)
    expect(isWalletAddress('0x413744D59d31AFDC2889aeE602636177805Bd7b')).to.equal(false)
    expect(isWalletAddress('413744D59d31AFDC2889aeE602636177805Bd7b0a')).to.equal(false)
    expect(isWalletAddress('0x' + 'g'.repeat(40))).to.equal(false)
    expect(isWalletAddress('0x' + 'a'.repeat(100000))).to.equal(false)
    expect(isWalletAddress({ length: 42 })).to.equal(false)
    expect(isWalletAddress(undefined)).to.equal(false)
  })

  it('rejects invalid wallet addresses with 400 without storing them', async () => {
    for (const walletAddress of ['x'.repeat(100000), { a: 1 }, ['0x' + 'a'.repeat(40)], undefined]) {
      await contractExploitListener()({ body: { walletAddress } } as any, res)
    }

    expect(res.status).to.have.always.been.calledWith(400)
    expect(walletsConnected.size).to.equal(0)
  })

  it('keeps the set of connected wallets bounded under a flood of unique addresses', () => {
    for (let i = 0; i < MAX_WALLETS_CONNECTED * 5; i++) {
      rememberWallet(address(i))
    }

    expect(walletsConnected.size).to.equal(MAX_WALLETS_CONNECTED)
    expect(walletsConnected.has(address(MAX_WALLETS_CONNECTED * 5 - 1))).to.equal(true)
    expect(walletsConnected.has(address(0))).to.equal(false)
  })

  it('expires connected wallets after the TTL', () => {
    rememberWallet(address(1), 0)
    rememberWallet(address(2), WALLET_TTL_MS)

    expect(walletsConnected.has(address(1))).to.equal(false)
    expect(walletsConnected.has(address(2))).to.equal(true)
    expect(consumeWallet(address(2), 2 * WALLET_TTL_MS)).to.equal(false)
    expect(walletsConnected.size).to.equal(0)
  })

  it('matches the on-chain exploiter address case-insensitively and only once', () => {
    rememberWallet('0x413744D59d31AFDC2889aeE602636177805Bd7b0')

    expect(walletsConnected.has('0x413744d59d31afdc2889aee602636177805bd7b0')).to.equal(true)
    expect(consumeWallet('0x413744D59d31AFDC2889aeE602636177805Bd7b0')).to.equal(true)
    expect(consumeWallet('0x413744D59d31AFDC2889aeE602636177805Bd7b0')).to.equal(false)
  })

  it('shares one listener between concurrent registrations and solves on the matching exploit event', async () => {
    const { ethers, providers, handlers } = fakeEthers()
    sinon.stub(exploitListenerDeps, 'loadEthers').resolves(ethers)
    const otherRes = mockRes()

    await Promise.all([
      contractExploitListener()({ body: { walletAddress: '0x413744D59d31AFDC2889aeE602636177805Bd7b0' } } as any, res),
      contractExploitListener()({ body: { walletAddress: address(7) } } as any, otherRes)
    ])

    expect(providers.length).to.equal(1)
    expect(handlers.length).to.equal(1)
    expect(res.status).to.have.been.calledWith(200)
    expect(otherRes.status).to.have.been.calledWith(200)

    handlers[0]('0x413744d59d31afdc2889aee602636177805bd7b0')
    expect(walletsConnected.has('0x413744d59d31afdc2889aee602636177805bd7b0')).to.equal(false)
    expect(walletsConnected.has(address(7))).to.equal(true)
  })

  it('forgets the wallet and closes the provider when the subscription fails, then retries', async () => {
    const failing = fakeEthers({ failSubscription: true })
    const loadEthers = sinon.stub(exploitListenerDeps, 'loadEthers').resolves(failing.ethers)

    await contractExploitListener()({ body: { walletAddress: address(1) } } as any, res)
    await nextTick()

    expect(res.status).to.have.been.calledWith(500)
    expect(walletsConnected.size).to.equal(0)
    expect(failing.providers[0].destroy.called).to.equal(true)

    const working = fakeEthers()
    loadEthers.resolves(working.ethers)
    const retryRes = mockRes()
    await contractExploitListener()({ body: { walletAddress: address(2) } } as any, retryRes)

    expect(retryRes.status).to.have.been.calledWith(200)
    expect(working.providers.length).to.equal(1)
    expect(walletsConnected.has(address(2))).to.equal(true)
  })

  it('closes a provider after a WebSocket error and ignores errors from replaced providers', async () => {
    const { ethers, providers } = fakeEthers()
    sinon.stub(exploitListenerDeps, 'loadEthers').resolves(ethers)

    await contractExploitListener()({ body: { walletAddress: address(1) } } as any, res)
    providers[0].websocket.onerror(new Error('socket closed'))
    await nextTick()
    expect(providers[0].destroy.called).to.equal(true)

    await contractExploitListener()({ body: { walletAddress: address(2) } } as any, mockRes())
    expect(providers.length).to.equal(2)

    providers[0].websocket.onerror(new Error('late error from old socket'))
    await contractExploitListener()({ body: { walletAddress: address(3) } } as any, mockRes())
    await nextTick()
    expect(providers.length).to.equal(2)
    expect(providers[1].destroy.called).to.equal(false)
  })
})
