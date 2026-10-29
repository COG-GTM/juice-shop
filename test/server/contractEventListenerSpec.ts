/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { ContractEventListener, type ListenerProvider, type RetryScheduler } from '../../lib/contractEventListener'
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

interface ScheduledRetry { retry: () => void, delayMs: number, cancelled: boolean }

describe('contractEventListener', () => {
  let clock: number
  let providers: FakeProvider[]
  let scheduled: ScheduledRetry[]
  let listener: ContractEventListener

  const schedule: RetryScheduler = (retry, delayMs) => {
    const entry = { retry, delayMs, cancelled: false }
    scheduled.push(entry)
    return () => { entry.cancelled = true }
  }
  const pending = () => scheduled.filter(entry => !entry.cancelled)
  const runScheduledRetry = async () => {
    const entry = pending()[0]
    scheduled.splice(scheduled.indexOf(entry), 1)
    clock += entry.delayMs
    entry.retry()
    await new Promise(resolve => setImmediate(resolve))
  }
  const createListener = (connect: (fail: (error: unknown) => void) => Promise<ListenerProvider>) =>
    new ContractEventListener('Test Listener', connect, 1000, () => clock, schedule, 8000)

  beforeEach(() => {
    clock = 0
    providers = []
    scheduled = []
    listener = createListener(async () => {
      const provider = new FakeProvider()
      providers.push(provider)
      return provider
    })
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
    listener = createListener(async () => {
      attempts++
      throw new Error('boom')
    })
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
    listener = createListener(async () => {
      const provider = new FakeProvider()
      provider.destroy = () => { throw new Error('websocket closed') }
      providers.push(provider)
      return provider
    })
    await listener.ensureStarted()
    expect(() => { providers[0].fail() }).to.not.throw()
    expect(listener.isActive()).to.equal(false)
  })

  it('releases the provider when the event subscription fails after connecting', async () => {
    let failSubscription: (error: unknown) => void = () => {}
    listener = createListener(async (fail) => {
      failSubscription = fail
      const provider = new FakeProvider()
      providers.push(provider)
      return provider
    })
    await listener.ensureStarted()
    failSubscription(new Error('eth_subscribe rejected'))
    expect(providers[0].destroyed).to.equal(1)
    expect(listener.isActive()).to.equal(false)
    await listener.ensureStarted()
    expect(providers.length).to.equal(1)
    clock = 1000
    await listener.ensureStarted()
    expect(providers.length).to.equal(2)
    expect(listener.isActive()).to.equal(true)
  })

  it('rejects and destroys the provider when the subscription fails before connecting completes', async () => {
    listener = createListener(async (fail) => {
      const provider = new FakeProvider()
      providers.push(provider)
      fail(new Error('eth_subscribe rejected'))
      return provider
    })
    try {
      await listener.ensureStarted()
      chai.assert.fail('Expected error was not thrown')
    } catch (error) {
      expect((error as Error).message).to.equal('eth_subscribe rejected')
    }
    expect(providers[0].destroyed).to.equal(1)
    expect(listener.isActive()).to.equal(false)
    await listener.ensureStarted()
    expect(providers.length).to.equal(1)
  })

  it('reconnects on its own after the retry delay without another request', async () => {
    await listener.ensureStarted()
    providers[0].fail()
    expect(pending().map(entry => entry.delayMs)).to.deep.equal([1000])
    await runScheduledRetry()
    expect(providers.length).to.equal(2)
    expect(listener.isActive()).to.equal(true)
    expect(pending().length).to.equal(0)
  })

  it('keeps a single pending retry no matter how many requests arrive during the cooldown', async () => {
    await listener.ensureStarted()
    providers[0].fail()
    for (let i = 0; i < 50; i++) await listener.ensureStarted()
    expect(pending().length).to.equal(1)
    expect(providers.length).to.equal(1)
  })

  it('backs off exponentially up to the maximum delay while the upstream keeps failing', async () => {
    const delays: number[] = []
    await listener.ensureStarted()
    for (let i = 0; i < 6; i++) {
      providers[providers.length - 1].fail()
      delays.push(pending()[0].delayMs)
      await runScheduledRetry()
    }
    expect(delays).to.deep.equal([1000, 2000, 4000, 8000, 8000, 8000])
    expect(providers.filter(p => p.destroyed === 0).length).to.equal(1)
  })

  it('resets the backoff once a provider stayed connected for the maximum delay', async () => {
    await listener.ensureStarted()
    for (let i = 0; i < 3; i++) {
      providers[providers.length - 1].fail()
      await runScheduledRetry()
    }
    clock += 8000
    providers[providers.length - 1].fail()
    expect(pending()[0].delayMs).to.equal(1000)
  })

  it('cancels the pending retry when stopped', async () => {
    await listener.ensureStarted()
    providers[0].fail()
    listener.stop()
    expect(pending().length).to.equal(0)
  })
})
