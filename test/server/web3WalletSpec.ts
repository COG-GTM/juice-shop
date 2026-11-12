/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import {
  contractExploitListener,
  consumeWallet,
  isWalletAddress,
  LISTENER_RETRY_DELAY_MS,
  listenerDeps,
  MAX_WALLETS_CONNECTED,
  rememberWallet,
  resetExploitListener,
  WALLET_TTL_MS,
  walletsConnected
} from '../../routes/web3Wallet'
const expect = chai.expect
chai.use(sinonChai)

const address = (n: number) => '0x' + n.toString(16).padStart(40, '0')

describe('web3Wallet', () => {
  let res: any

  beforeEach(() => {
    walletsConnected.clear()
    res = { status: sinon.stub(), json: sinon.spy() }
    res.status.returns(res)
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

  describe('contract exploit listener', () => {
    let providers: any[]
    let now: number
    let exploitHandler: ((exploiter: string) => void) | undefined
    let subscribeError: Error | undefined
    const originalDeps = { ...listenerDeps }
    const validRequest = () => ({ body: { walletAddress: address(1) } }) as any

    beforeEach(() => {
      resetExploitListener()
      providers = []
      now = 0
      exploitHandler = undefined
      subscribeError = undefined
      class WebSocketProvider {
        websocket: any = { onerror: null }
        destroy = sinon.spy()
        constructor () { providers.push(this) }
      }
      class Contract {
        async on (event: string, handler: (exploiter: string) => void) {
          if (subscribeError !== undefined) throw subscribeError
          if (event === 'ContractExploited') exploitHandler = handler
        }
      }
      listenerDeps.loadEthers = async () => ({ WebSocketProvider, Contract }) as any
      listenerDeps.now = () => now
    })

    afterEach(() => {
      Object.assign(listenerDeps, originalDeps)
      resetExploitListener()
    })

    it('opens a single provider for concurrent requests', async () => {
      await Promise.all(Array.from({ length: 20 }, async () => { await contractExploitListener()(validRequest(), res) }))

      expect(providers.length).to.equal(1)
      expect(res.status).to.have.always.been.calledWith(200)
    })

    it('solves the challenge once when a registered wallet exploits the contract', async () => {
      challenges.web3WalletChallenge = { solved: false, save: () => ({ then () {} }) } as unknown as Challenge
      await contractExploitListener()(validRequest(), res)

      exploitHandler?.(address(2))
      expect(challenges.web3WalletChallenge.solved).to.equal(false)

      exploitHandler?.(address(1).toUpperCase().replace('0X', '0x'))
      expect(challenges.web3WalletChallenge.solved).to.equal(true)
      expect(walletsConnected.size).to.equal(0)
    })

    it('destroys the provider and stores nothing when subscribing to the contract fails', async () => {
      subscribeError = new Error('subscribe failed')

      await contractExploitListener()(validRequest(), res)

      expect(res.status).to.have.been.calledWith(500)
      expect(providers.length).to.equal(1)
      expect(providers[0].destroy.calledOnce).to.equal(true)
      expect(walletsConnected.size).to.equal(0)

      subscribeError = undefined
      await contractExploitListener()(validRequest(), res)
      expect(providers.length).to.equal(1)

      now = LISTENER_RETRY_DELAY_MS
      await contractExploitListener()(validRequest(), res)
      expect(providers.length).to.equal(2)
      expect(res.status).to.have.been.calledWith(200)
      expect(walletsConnected.has(address(1))).to.equal(true)
    })

    it('destroys a failed provider and throttles reconnects', async () => {
      await contractExploitListener()(validRequest(), res)
      providers[0].websocket.onerror(new Error('401'))

      expect(providers[0].destroy.calledOnce).to.equal(true)
      for (let i = 0; i < 10; i++) {
        await contractExploitListener()(validRequest(), res)
      }
      expect(providers.length).to.equal(1)
      expect(res.status).to.have.been.calledWith(500)

      now = LISTENER_RETRY_DELAY_MS
      await contractExploitListener()(validRequest(), res)
      expect(providers.length).to.equal(2)
    })

    it('does not keep a wallet registered when the listener cannot be created', async () => {
      await contractExploitListener()(validRequest(), res)
      providers[0].websocket.onerror(new Error('401'))

      await contractExploitListener()(({ body: { walletAddress: address(2) } }) as any, res)

      expect(res.status).to.have.been.calledWith(500)
      expect(walletsConnected.has(address(2))).to.equal(false)
      expect(walletsConnected.has(address(1))).to.equal(true)
    })

    it('does not evict pending wallets when a registration fails on a full set', async () => {
      await contractExploitListener()(validRequest(), res)
      providers[0].websocket.onerror(new Error('401'))
      walletsConnected.clear()
      for (let i = 0; i < MAX_WALLETS_CONNECTED; i++) {
        rememberWallet(address(i), now)
      }

      await contractExploitListener()(({ body: { walletAddress: address(MAX_WALLETS_CONNECTED) } }) as any, res)

      expect(res.status).to.have.been.calledWith(500)
      expect(walletsConnected.size).to.equal(MAX_WALLETS_CONNECTED)
      expect(walletsConnected.has(address(0))).to.equal(true)
      expect(walletsConnected.has(address(MAX_WALLETS_CONNECTED))).to.equal(false)
    })
  })
})
