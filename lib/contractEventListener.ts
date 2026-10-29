/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import logger from './logger'

export interface ListenerProvider {
  websocket: { onerror: ((error: any) => void) | null, onclose?: ((event: any) => void) | null }
  destroy: () => unknown
}

export type RetryScheduler = (retry: () => void, delayMs: number) => () => void

export const RETRY_DELAY_MS = 60 * 1000
export const MAX_RETRY_DELAY_MS = 15 * 60 * 1000

const scheduleUnrefTimeout: RetryScheduler = (retry, delayMs) => {
  const timer = setTimeout(retry, delayMs)
  timer.unref()
  return () => { clearTimeout(timer) }
}

// Keeps at most one blockchain WebSocket provider alive per listener. A failed
// provider is destroyed before a new one may be opened, and reconnects happen
// on a single timer with exponential backoff, so neither repeated requests nor
// a broken upstream can pile up outbound connections.
export class ContractEventListener {
  private provider: ListenerProvider | null = null
  private connecting: Promise<void> | null = null
  private lastFailureAt: number | null = null
  private connectedAt: number | null = null
  private consecutiveFailures = 0
  private cancelRetry: (() => void) | null = null

  constructor (
    private readonly name: string,
    private readonly connect: (fail: (error: unknown) => void) => Promise<ListenerProvider>,
    private readonly retryDelayMs = RETRY_DELAY_MS,
    private readonly now: () => number = Date.now,
    private readonly schedule: RetryScheduler = scheduleUnrefTimeout,
    private readonly maxRetryDelayMs = MAX_RETRY_DELAY_MS
  ) {}

  isActive (): boolean {
    return this.provider !== null
  }

  async ensureStarted (): Promise<void> {
    if (this.lastFailureAt !== null && this.provider === null && this.connecting === null &&
      this.now() - this.lastFailureAt < this.currentRetryDelay()) return
    await this.start()
  }

  stop (): void {
    this.cancelRetry?.()
    this.cancelRetry = null
    if (this.provider !== null) this.release(this.provider, false)
  }

  private async start (): Promise<void> {
    if (this.provider !== null) return
    if (this.connecting !== null) return await this.connecting
    this.connecting = this.open().finally(() => { this.connecting = null })
    return await this.connecting
  }

  private currentRetryDelay (): number {
    return Math.min(this.retryDelayMs * 2 ** Math.max(this.consecutiveFailures - 1, 0), this.maxRetryDelayMs)
  }

  private recordFailure (): void {
    const now = this.now()
    if (this.connectedAt !== null && now - this.connectedAt >= this.maxRetryDelayMs) this.consecutiveFailures = 0
    this.connectedAt = null
    this.consecutiveFailures++
    this.lastFailureAt = now
    if (this.cancelRetry !== null) return
    this.cancelRetry = this.schedule(() => {
      this.cancelRetry = null
      this.start().catch(() => {})
    }, this.currentRetryDelay())
  }

  private async open (): Promise<void> {
    let provider: ListenerProvider | null = null
    const early: { failed: boolean, error?: unknown } = { failed: false }
    const fail = (error: unknown) => {
      logger.error(`Subscription error (${this.name}): ${(error as any)?.message ?? error}`)
      if (provider !== null) this.release(provider, true)
      else Object.assign(early, { failed: true, error })
    }
    try {
      provider = await this.connect(fail)
    } catch (error) {
      this.recordFailure()
      throw error
    }
    const current = provider
    this.provider = current
    this.connectedAt = this.now()
    if (early.failed) {
      this.release(current, true)
      throw early.error ?? new Error(`${this.name} subscription failed`)
    }
    current.websocket.onerror = (error: any) => {
      logger.error(`WebSocket error (${this.name}): ${error?.message ?? error}`)
      this.release(current, true)
    }
    current.websocket.onclose = () => {
      this.release(current, true)
    }
  }

  private release (provider: ListenerProvider, failed: boolean): void {
    if (this.provider !== provider) return
    this.provider = null
    if (failed) this.recordFailure()
    try {
      provider.websocket.onerror = null
      provider.websocket.onclose = null
      Promise.resolve(provider.destroy()).catch(() => {})
    } catch {}
  }
}
