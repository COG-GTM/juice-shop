/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import logger from './logger'

export interface ListenerProvider {
  websocket: { onerror: ((error: any) => void) | null, onclose?: ((event: any) => void) | null }
  destroy: () => unknown
}

export const RETRY_DELAY_MS = 60 * 1000

// Keeps at most one blockchain WebSocket provider alive per listener. A failed
// provider is destroyed before a new one may be opened, and reconnects are
// throttled so repeated requests cannot pile up outbound connections.
export class ContractEventListener {
  private provider: ListenerProvider | null = null
  private connecting: Promise<void> | null = null
  private lastFailureAt: number | null = null

  constructor (
    private readonly name: string,
    private readonly connect: (fail: (error: unknown) => void) => Promise<ListenerProvider>,
    private readonly retryDelayMs = RETRY_DELAY_MS,
    private readonly now: () => number = Date.now
  ) {}

  isActive (): boolean {
    return this.provider !== null
  }

  async ensureStarted (): Promise<void> {
    if (this.provider !== null) return
    if (this.connecting !== null) return await this.connecting
    if (this.lastFailureAt !== null && this.now() - this.lastFailureAt < this.retryDelayMs) return
    this.connecting = this.open().finally(() => { this.connecting = null })
    return await this.connecting
  }

  stop (): void {
    if (this.provider !== null) this.release(this.provider, false)
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
      this.lastFailureAt = this.now()
      throw error
    }
    const current = provider
    this.provider = current
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
    if (failed) this.lastFailureAt = this.now()
    try {
      provider.websocket.onerror = null
      provider.websocket.onclose = null
      Promise.resolve(provider.destroy()).catch(() => {})
    } catch {}
  }
}
