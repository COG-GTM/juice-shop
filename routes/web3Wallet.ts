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
  return now
}

function forgetWallet (address: string, registeredAt: number) {
  const normalized = address.toLowerCase()
  if (walletsConnected.get(normalized) === registeredAt) walletsConnected.delete(normalized)
}

export function consumeWallet (address: string, now = Date.now()) {
  pruneExpiredWallets(now)
  return walletsConnected.delete(address.toLowerCase())
}

interface ExploitListenerProvider {
  websocket: { onerror: ((error: any) => unknown) | null }
  destroy: () => unknown
}

export const exploitListenerDeps = {
  loadEthers: async () => await import('ethers')
}
let activeProvider: ExploitListenerProvider | null = null

function teardownProvider (provider: ExploitListenerProvider) {
  if (activeProvider === provider) activeProvider = null
  void Promise.resolve().then(async () => { await provider.destroy() }).catch((error) => {
    logger.warn(`Could not close Contract Exploit Listener provider: ${utils.getErrorMessage(error)}`)
  })
}

export function stopExploitListener () {
  exploitListener = null
  if (activeProvider !== null) teardownProvider(activeProvider)
}

function ensureExploitListener (): Promise<void> {
  if (exploitListener === null) {
    const setup: Promise<void> = (async () => {
      const { WebSocketProvider, Contract } = await exploitListenerDeps.loadEthers()
      const provider: ExploitListenerProvider = new WebSocketProvider(`wss://eth-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY ?? ''}`) as any
      activeProvider = provider
      provider.websocket.onerror = (error: any) => {
        logger.error(`WebSocket error (Contract Exploit Listener): ${error.message || error}`)
        if (exploitListener === setup) exploitListener = null
        teardownProvider(provider)
      }
      try {
        const contract = new Contract(web3WalletAddress, web3WalletABI, provider as any)
        await contract.on('ContractExploited', (exploiter: string) => {
          if (consumeWallet(exploiter)) {
            challengeUtils.solveIf(challenges.web3WalletChallenge, () => true)
          }
        })
      } catch (error) {
        teardownProvider(provider)
        throw error
      }
    })().catch((error) => {
      if (exploitListener === setup) exploitListener = null
      throw error
    })
    exploitListener = setup
  }
  return exploitListener
}

export function contractExploitListener () {
  return async (req: Request, res: Response) => {
    const metamaskAddress = req.body?.walletAddress
    if (!isWalletAddress(metamaskAddress)) {
      res.status(400).json({ success: false, message: 'Invalid wallet address' })
      return
    }
    const registeredAt = rememberWallet(metamaskAddress)
    try {
      await ensureExploitListener()
      res.status(200).json({ success: true, message: 'Event Listener Created' })
    } catch (error) {
      forgetWallet(metamaskAddress, registeredAt)
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
