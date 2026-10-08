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

    function fail (l: FailedAttemptLockout, key: string, times = 1) {
      for (let i = 0; i < times; i++) {
        expect(l.admit(key)).to.equal(0)
        l.recordFailure(key)
      }
    }

    beforeEach(() => {
      now = 1_000_000
      lockout = new FailedAttemptLockout(3, 60_000, 300_000, () => now)
    })

    it('does not lock below the failure threshold', () => {
      fail(lockout, 'a', 2)
      expect(lockout.retryAfterSeconds('a')).to.equal(0)
      expect(lockout.admit('a')).to.equal(0)
    })

    it('locks the key once the threshold is reached', () => {
      fail(lockout, 'a', 3)
      expect(lockout.retryAfterSeconds('a')).to.equal(300)
      expect(lockout.admit('a')).to.equal(300)
      expect(lockout.admit('b')).to.equal(0)
    })

    it('unlocks after the lock period', () => {
      fail(lockout, 'a', 3)
      now += 299_000
      expect(lockout.admit('a')).to.equal(1)
      now += 1_000
      expect(lockout.admit('a')).to.equal(0)
    })

    it('forgets failures older than the window', () => {
      fail(lockout, 'a', 2)
      now += 60_000
      fail(lockout, 'a')
      expect(lockout.retryAfterSeconds('a')).to.equal(0)
    })

    it('clears failures on reset', () => {
      fail(lockout, 'a', 2)
      lockout.reset('a')
      fail(lockout, 'a')
      expect(lockout.retryAfterSeconds('a')).to.equal(0)
    })

    it('counts in-flight attempts so parallel attempts cannot exceed the threshold', () => {
      const admitted = [0, 1, 2, 3, 4].map(() => lockout.admit('a')).filter(retryAfter => retryAfter === 0)
      expect(admitted).to.have.length(3)
      for (let i = 0; i < 3; i++) lockout.recordFailure('a')
      expect(lockout.admit('a')).to.equal(300)
    })

    it('does not count released attempts as failures', () => {
      for (let i = 0; i < 10; i++) {
        expect(lockout.admit('a')).to.equal(0)
        lockout.release('a')
      }
      expect(lockout.retryAfterSeconds('a')).to.equal(0)
      fail(lockout, 'a', 2)
      expect(lockout.retryAfterSeconds('a')).to.equal(0)
    })

    it('forgets keys whose only attempts were released', () => {
      expect(lockout.admit('unknown')).to.equal(0)
      lockout.release('unknown')
      expect((lockout as any).records.size).to.equal(0)
    })

    it('keeps tracking failures when a later attempt is released', () => {
      fail(lockout, 'a', 2)
      expect(lockout.admit('a')).to.equal(0)
      lockout.release('a')
      fail(lockout, 'a')
      expect(lockout.retryAfterSeconds('a')).to.equal(300)
    })

    it('reuses expired entries when the table is full', () => {
      const small = new FailedAttemptLockout(3, 60_000, 300_000, () => now, 2)
      fail(small, 'a')
      fail(small, 'b')
      now += 60_000
      expect(small.admit('c')).to.equal(0)
      expect((small as any).records.size).to.equal(1)
    })

    it('refuses new keys instead of evicting tracked ones when the table is full', () => {
      const small = new FailedAttemptLockout(2, 60_000, 300_000, () => now, 2)
      fail(small, 'victim', 2)
      fail(small, 'other')
      expect(small.admit('fresh')).to.equal(60)
      expect((small as any).records.size).to.equal(2)
      expect(small.admit('victim')).to.equal(300)
    })
  })
})
