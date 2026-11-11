/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import logger from './logger'

interface ListenerProvider {
  websocket: { onerror: ((error: any) => void) | null }
  destroy: () => void | Promise<void>
}

interface ContractListenerOptions {
  name: string
  address: string
  abi: any
  event: string
  onEvent: (...args: any[]) => void | Promise<void>
  retryDelayMs?: number
  createProvider?: () => Promise<ListenerProvider>
}

async function createAlchemyProvider (): Promise<ListenerProvider> {
  const { WebSocketProvider } = await import('ethers')
  return new WebSocketProvider(`wss://eth-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY ?? ''}`)
}

export function createContractListener ({ name, address, abi, event, onEvent, retryDelayMs = 30000, createProvider = createAlchemyProvider }: ContractListenerOptions) {
  let active: Promise<void> | null = null
  let provider: ListenerProvider | null = null
  let lastAttempt = 0

  const reset = (failed: ListenerProvider | null) => {
    if (failed !== provider) return
    active = null
    provider = null
    if (failed) {
      try {
        void Promise.resolve(failed.destroy()).catch(() => {})
      } catch {}
    }
  }

  const start = async () => {
    const current = await createProvider()
    provider = current
    current.websocket.onerror = (error: any) => {
      logger.error(`WebSocket error (${name}): ${error?.message || error}`)
      reset(current)
    }
    const { Contract } = await import('ethers')
    const contract = new Contract(address, abi, current as any)
    contract.on(event, onEvent).catch((error: any) => {
      logger.error(`Subscription error (${name}): ${error?.message || error}`)
      reset(current)
    })
  }

  return async function ensureListening (): Promise<boolean> {
    if (active) {
      await active
      return active !== null
    }
    const now = Date.now()
    if (now - lastAttempt < retryDelayMs) return false
    lastAttempt = now
    const attempt = start()
    active = attempt
    try {
      await attempt
      return active === attempt
    } catch (error) {
      if (active === attempt) {
        reset(provider)
        active = null
      }
      throw error
    }
  }
}

export function addBounded<T> (set: Set<T>, value: T, maxSize: number) {
  set.delete(value)
  set.add(value)
  while (set.size > maxSize) {
    const oldest = set.values().next().value as T
    set.delete(oldest)
  }
}
