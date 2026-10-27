/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { ContractEventListener, type ListenerProvider } from '../../lib/contractEventListener'
const expect = chai.expect

class FakeProvider implements ListenerProvider {
  websocket: { onerror: ((error: any) => void) | null, onclose: ((event: any) => void) | null } = { onerror: null, onclose: null }
  destroyed = 0

  destroy () {
    this.destroyed++
  }

  fail () {
    this.websocket.onerror?.(new Error('Unexpected server response: 401'))
    this.websocket.onclose?.({ code: 1006 })
  }
}

describe('contractEventListener', () => {
  let clock: number
  let providers: FakeProvider[]
  let listener: ContractEventListener

  beforeEach(() => {
    clock = 0
    providers = []
    listener = new ContractEventListener('Test Listener', async () => {
      const provider = new FakeProvider()
      providers.push(provider)
      return provider
    }, 1000, () => clock)
  })

  it('opens only one provider for repeated requests', async () => {
    for (let i = 0; i < 50; i++) await listener.ensureStarted()
    expect(providers.length).to.equal(1)
    expect(listener.isActive()).to.equal(true)
  })

  it('opens only one provider for concurrent requests', async () => {
    await Promise.all(Array.from({ length: 50 }, async () => { await listener.ensureStarted() }))
    expect(providers.length).to.equal(1)
  })

  it('destroys a failed provider exactly once', async () => {
    await listener.ensureStarted()
    providers[0].fail()
    providers[0].fail()
    expect(providers[0].destroyed).to.equal(1)
    expect(listener.isActive()).to.equal(false)
  })

  it('does not reconnect before the retry delay has passed', async () => {
    await listener.ensureStarted()
    providers[0].fail()
    clock = 999
    for (let i = 0; i < 50; i++) await listener.ensureStarted()
    expect(providers.length).to.equal(1)
  })

  it('reconnects with a fresh provider after the retry delay', async () => {
    await listener.ensureStarted()
    providers[0].fail()
    clock = 1000
    await listener.ensureStarted()
    expect(providers.length).to.equal(2)
    expect(providers[0].destroyed).to.equal(1)
    expect(providers[1].destroyed).to.equal(0)
    expect(listener.isActive()).to.equal(true)
  })

  it('keeps at most one live provider across many error-and-request cycles', async () => {
    for (let i = 0; i < 100; i++) {
      await listener.ensureStarted()
      providers[providers.length - 1].fail()
      clock += 1000
    }
    expect(providers.filter(p => p.destroyed === 0).length).to.equal(0)
    expect(providers.every(p => p.destroyed === 1)).to.equal(true)
  })

  it('applies the retry delay when connecting throws', async () => {
    let attempts = 0
    listener = new ContractEventListener('Test Listener', async () => {
      attempts++
      throw new Error('boom')
    }, 1000, () => clock)
    try {
      await listener.ensureStarted()
      chai.assert.fail('Expected error was not thrown')
    } catch (error) {
      expect((error as Error).message).to.equal('boom')
    }
    await listener.ensureStarted()
    expect(attempts).to.equal(1)
  })

  it('ignores errors thrown while destroying a provider', async () => {
    listener = new ContractEventListener('Test Listener', async () => {
      const provider = new FakeProvider()
      provider.destroy = () => { throw new Error('websocket closed') }
      providers.push(provider)
      return provider
    }, 1000, () => clock)
    await listener.ensureStarted()
    expect(() => { providers[0].fail() }).to.not.throw()
    expect(listener.isActive()).to.equal(false)
  })
})
