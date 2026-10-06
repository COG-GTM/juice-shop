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
let isEventListenerCreated = false

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
  walletsConnected.delete(address)
  walletsConnected.set(address, now)
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

export function contractExploitListener () {
  return async (req: Request, res: Response) => {
    const metamaskAddress = req.body?.walletAddress
    if (!isWalletAddress(metamaskAddress)) {
      res.status(400).json({ success: false, message: 'Invalid wallet address' })
      return
    }
    rememberWallet(metamaskAddress.toLowerCase())
    try {
      if (!isEventListenerCreated) {
        const { WebSocketProvider, Contract } = await import('ethers')
        const provider = new WebSocketProvider(`wss://eth-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY ?? ''}`)
        provider.websocket.onerror = (error: any) => {
          logger.error(`WebSocket error (Contract Exploit Listener): ${error.message || error}`)
          isEventListenerCreated = false
        }
        const contract = new Contract(web3WalletAddress, web3WalletABI, provider as any)
        void contract.on('ContractExploited', (exploiter: string) => {
          if (consumeWallet(exploiter)) {
            challengeUtils.solveIf(challenges.web3WalletChallenge, () => true)
          }
        })
        isEventListenerCreated = true
      }
      res.status(200).json({ success: true, message: 'Event Listener Created' })
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
