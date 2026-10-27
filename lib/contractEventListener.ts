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
    private readonly connect: () => Promise<ListenerProvider>,
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
    let provider: ListenerProvider
    try {
      provider = await this.connect()
    } catch (error) {
      this.lastFailureAt = this.now()
      throw error
    }
    this.provider = provider
    provider.websocket.onerror = (error: any) => {
      logger.error(`WebSocket error (${this.name}): ${error?.message ?? error}`)
      this.release(provider, true)
    }
    provider.websocket.onclose = () => {
      this.release(provider, true)
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
