import { type Request, type Response } from 'express'

import logger from '../lib/logger'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'
import { web3WalletABI } from '../data/static/contractABIs'

const web3WalletAddress = '0x413744D59d31AFDC2889aeE602636177805Bd7b0'
const ETH_ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/
export const MAX_WALLETS_CONNECTED = 1000
export const WALLET_TTL_MS = 60 * 60 * 1000
export const walletsConnected = new Map<string, number>()
let exploitListener: Promise<void> | null = null

export function isWalletAddress (address: unknown): address is string {
  return typeof address === 'string' && ETH_ADDRESS_PATTERN.test(address)
}

function pruneExpiredWallets (now: number) {
  for (const [address, connectedAt] of walletsConnected) {
    if (now - connectedAt < WALLET_TTL_MS) break
    walletsConnected.delete(address)
  }
}

export function rememberWallet (address: string, now = Date.now()) {
  pruneExpiredWallets(now)
  const normalized = address.toLowerCase()
  walletsConnected.delete(normalized)
  walletsConnected.set(normalized, now)
  while (walletsConnected.size > MAX_WALLETS_CONNECTED) {
    const oldest = walletsConnected.keys().next().value
    if (oldest === undefined) break
    walletsConnected.delete(oldest)
  }
}

export function consumeWallet (address: string, now = Date.now()) {
  pruneExpiredWallets(now)
  return walletsConnected.delete(address.toLowerCase())
}

interface ExploitProvider {
  websocket: { onerror: ((error: any) => void) | null }
  destroy: () => unknown
}

export const LISTENER_RETRY_DELAY_MS = 60 * 1000
export const listenerDeps = {
  loadEthers: async () => await import('ethers'),
  now: () => Date.now()
}
let lastListenerFailureAt: number | null = null

export function resetExploitListener () {
  exploitListener = null
  lastListenerFailureAt = null
}

function releaseExploitListener (listener: Promise<void>, provider?: ExploitProvider) {
  if (exploitListener !== listener) return
  exploitListener = null
  lastListenerFailureAt = listenerDeps.now()
  if (provider !== undefined) {
    provider.websocket.onerror = null
    try {
      void Promise.resolve(provider.destroy()).catch(() => {})
    } catch {}
  }
}

function ensureExploitListener (): Promise<void> {
  if (exploitListener !== null) return exploitListener
  if (lastListenerFailureAt !== null && listenerDeps.now() - lastListenerFailureAt < LISTENER_RETRY_DELAY_MS) {
    return Promise.reject(new Error('Contract exploit listener is temporarily unavailable'))
  }
  let provider: ExploitProvider | undefined
  const listener: Promise<void> = (async () => {
    const { WebSocketProvider, Contract } = await listenerDeps.loadEthers()
    const wsProvider = new WebSocketProvider(`wss://eth-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY ?? ''}`)
    provider = wsProvider as unknown as ExploitProvider
    provider.websocket.onerror = (error: any) => {
      logger.error(`WebSocket error (Contract Exploit Listener): ${error?.message ?? error}`)
      releaseExploitListener(listener, provider)
    }
    const contract = new Contract(web3WalletAddress, web3WalletABI, wsProvider as any)
    await contract.on('ContractExploited', (exploiter: string) => {
      if (consumeWallet(exploiter)) {
        challengeUtils.solveIf(challenges.web3WalletChallenge, () => true)
      }
    })
  })()
  exploitListener = listener
  void listener.catch(() => { releaseExploitListener(listener, provider) })
  return listener
}

export function contractExploitListener () {
  return async (req: Request, res: Response) => {
    const metamaskAddress = req.body?.walletAddress
    if (!isWalletAddress(metamaskAddress)) {
      res.status(400).json({ success: false, message: 'Invalid wallet address' })
      return
    }
    try {
      await ensureExploitListener()
      rememberWallet(metamaskAddress)
      res.status(200).json({ success: true, message: 'Event Listener Created' })
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
