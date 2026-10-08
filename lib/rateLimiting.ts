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
  pending: number
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
    private readonly maxEntries = 100000
  ) {}

  retryAfterSeconds (key: string): number {
    const record = this.records.get(key)
    if (record == null) return 0
    const remaining = record.lockedUntil - this.now()
    return remaining > 0 ? Math.ceil(remaining / 1000) : 0
  }

  /* Returns 0 and reserves an attempt, or the seconds to wait. In-flight attempts count against the limit so parallel requests cannot exceed it.
     Every admitted attempt must end with recordFailure(), release() or reset(). When the table is full, unknown keys are refused rather than evicting tracked ones. */
  admit (key: string): number {
    const now = this.now()
    let record = this.records.get(key)
    if (record == null) {
      if (this.records.size >= this.maxEntries) this.prune(now)
      if (this.records.size >= this.maxEntries) return Math.ceil(this.windowMs / 1000)
      record = { failures: 0, pending: 0, windowStart: now, lockedUntil: 0 }
      this.records.set(key, record)
    }
    if (record.lockedUntil > now) return Math.ceil((record.lockedUntil - now) / 1000)
    this.expireWindow(record, now)
    if (record.failures + record.pending >= this.maxFailures) return 1
    record.pending++
    return 0
  }

  recordFailure (key: string) {
    const record = this.records.get(key)
    if (record == null) return
    const now = this.now()
    record.pending = Math.max(0, record.pending - 1)
    this.expireWindow(record, now)
    record.failures++
    if (record.failures >= this.maxFailures) {
      record.lockedUntil = now + this.lockMs
      record.failures = 0
      record.windowStart = now
    }
  }

  /* Gives back an admitted attempt that ended without checking an answer (e.g. unknown account or database error) and forgets keys with nothing left to track */
  release (key: string) {
    const record = this.records.get(key)
    if (record == null) return
    record.pending = Math.max(0, record.pending - 1)
    if (record.pending === 0 && record.failures === 0 && record.lockedUntil <= this.now()) this.records.delete(key)
  }

  reset (key: string) {
    this.records.delete(key)
  }

  private expireWindow (record: AttemptRecord, now: number) {
    if (record.lockedUntil <= now && now - record.windowStart >= this.windowMs) {
      record.failures = 0
      record.windowStart = now
    }
  }

  private prune (now: number) {
    for (const [key, record] of this.records) {
      if (record.pending === 0 && record.lockedUntil <= now && now - record.windowStart >= this.windowMs) this.records.delete(key)
    }
  }
}

export function accountKey (email: unknown) {
  return String(email).trim().toLowerCase()
}

export const passwordResetLockout = new FailedAttemptLockout()
