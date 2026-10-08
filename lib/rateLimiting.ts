/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/* Number of reverse proxies in front of the server. Without any, req.ip is the socket address and cannot be spoofed via X-Forwarded-For */
export function trustedProxyHops (value = process.env.JUICE_SHOP_TRUSTED_PROXY_HOPS): number | false {
  const hops = Number(value)
  return value !== undefined && value.trim() !== '' && Number.isInteger(hops) && hops > 0 ? hops : false
}

interface AttemptRecord {
  failures: number
  windowStart: number
  lockedUntil: number
}

/* Locks a key (e.g. an account) after repeated failures, regardless of which client address the attempts come from */
export class FailedAttemptLockout {
  private readonly records = new Map<string, AttemptRecord>()

  constructor (
    readonly maxFailures = 10,
    readonly windowMs = 15 * 60 * 1000,
    readonly lockMs = 15 * 60 * 1000,
    private readonly now: () => number = Date.now,
    private readonly maxEntries = 10000
  ) {}

  retryAfterSeconds (key: string): number {
    const record = this.records.get(key)
    if (record == null) return 0
    const remaining = record.lockedUntil - this.now()
    return remaining > 0 ? Math.ceil(remaining / 1000) : 0
  }

  // Checks and counts in one synchronous step so concurrent requests cannot all pass the check before any is counted.
  // Callers reset() the key after a successful attempt.
  consumeAttempt (key: string): number {
    const retryAfter = this.retryAfterSeconds(key)
    if (retryAfter === 0) this.recordFailure(key)
    return retryAfter
  }

  recordFailure (key: string) {
    const now = this.now()
    let record = this.records.get(key)
    if (record == null || (record.lockedUntil <= now && now - record.windowStart >= this.windowMs)) {
      if (record == null && this.records.size >= this.maxEntries) this.makeRoom(now)
      record = { failures: 0, windowStart: now, lockedUntil: 0 }
      this.records.set(key, record)
    }
    record.failures++
    if (record.failures >= this.maxFailures) {
      record.lockedUntil = now + this.lockMs
      record.failures = 0
      record.windowStart = now
    }
  }

  reset (key: string) {
    this.records.delete(key)
  }

  private makeRoom (now: number) {
    for (const [key, record] of this.records) {
      if (record.lockedUntil <= now && now - record.windowStart >= this.windowMs) this.records.delete(key)
    }
    if (this.records.size < this.maxEntries) return
    for (const [key, record] of this.records) {
      if (record.lockedUntil <= now) {
        this.records.delete(key)
        return
      }
    }
    const oldest = this.records.keys().next().value
    if (oldest !== undefined) this.records.delete(oldest)
  }
}

export function accountKey (email: unknown) {
  return String(email).trim().toLowerCase()
}

export const passwordResetLockout = new FailedAttemptLockout()
