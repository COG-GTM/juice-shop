/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'

import { accountKey, FailedAttemptLockout, trustedProxyHops } from '../../lib/rateLimiting'
const expect = chai.expect

describe('rateLimiting', () => {
  describe('trustedProxyHops', () => {
    it('does not trust any proxy by default', () => {
      expect(trustedProxyHops(undefined)).to.equal(false)
      expect(trustedProxyHops('')).to.equal(false)
    })

    it('trusts the configured number of proxy hops', () => {
      expect(trustedProxyHops('1')).to.equal(1)
      expect(trustedProxyHops(' 2 ')).to.equal(2)
    })

    it('ignores invalid values', () => {
      for (const value of ['0', '-1', '1.5', 'true', 'abc']) {
        expect(trustedProxyHops(value)).to.equal(false)
      }
    })
  })

  describe('accountKey', () => {
    it('normalizes case and whitespace so variants of one email share a lockout', () => {
      expect(accountKey(' Jim@Juice-sh.op ')).to.equal('jim@juice-sh.op')
    })
  })

  describe('FailedAttemptLockout', () => {
    let now: number
    let lockout: FailedAttemptLockout

    beforeEach(() => {
      now = 1_000_000
      lockout = new FailedAttemptLockout(3, 60_000, 300_000, () => now)
    })

    it('does not lock below the failure threshold', () => {
      lockout.recordFailure('a')
      lockout.recordFailure('a')
      expect(lockout.retryAfterSeconds('a')).to.equal(0)
    })

    it('locks the key once the threshold is reached', () => {
      for (let i = 0; i < 3; i++) lockout.recordFailure('a')
      expect(lockout.retryAfterSeconds('a')).to.equal(300)
      expect(lockout.retryAfterSeconds('b')).to.equal(0)
    })

    it('unlocks after the lock period', () => {
      for (let i = 0; i < 3; i++) lockout.recordFailure('a')
      now += 299_000
      expect(lockout.retryAfterSeconds('a')).to.equal(1)
      now += 1_000
      expect(lockout.retryAfterSeconds('a')).to.equal(0)
    })

    it('forgets failures older than the window', () => {
      lockout.recordFailure('a')
      lockout.recordFailure('a')
      now += 60_000
      lockout.recordFailure('a')
      expect(lockout.retryAfterSeconds('a')).to.equal(0)
    })

    it('clears failures on reset', () => {
      lockout.recordFailure('a')
      lockout.recordFailure('a')
      lockout.reset('a')
      lockout.recordFailure('a')
      expect(lockout.retryAfterSeconds('a')).to.equal(0)
    })

    it('bounds memory by pruning expired entries', () => {
      const small = new FailedAttemptLockout(3, 60_000, 300_000, () => now, 2)
      small.recordFailure('a')
      small.recordFailure('b')
      now += 60_000
      small.recordFailure('c')
      expect((small as any).records.size).to.equal(1)
    })

    it('counts an attempt when it is admitted so parallel attempts cannot exceed the threshold', () => {
      const admitted = [0, 1, 2, 3, 4].map(() => lockout.consumeAttempt('a')).filter(retryAfter => retryAfter === 0)
      expect(admitted).to.have.length(3)
      expect(lockout.retryAfterSeconds('a')).to.equal(300)
    })

    it('does not count attempts rejected while locked', () => {
      for (let i = 0; i < 3; i++) lockout.consumeAttempt('a')
      expect(lockout.consumeAttempt('a')).to.equal(300)
      now += 300_000
      expect(lockout.consumeAttempt('a')).to.equal(0)
      expect(lockout.retryAfterSeconds('a')).to.equal(0)
    })

    it('never grows beyond its capacity, evicting unlocked entries before locked ones', () => {
      const small = new FailedAttemptLockout(2, 60_000, 300_000, () => now, 3)
      small.recordFailure('locked')
      small.recordFailure('locked')
      for (let i = 0; i < 10; i++) small.recordFailure(`fresh${i}`)
      expect((small as any).records.size).to.equal(3)
      expect(small.retryAfterSeconds('locked')).to.equal(300)
    })
  })
})
