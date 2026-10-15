import { type Request, type Response } from 'express'

import logger from '../lib/logger'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'
import { web3WalletABI } from '../data/static/contractABIs'

const web3WalletAddress = '0x413744D59d31AFDC2889aeE602636177805Bd7b0'
const walletAddressPattern = /^0x[0-9a-fA-F]{40}$/
export const maxWalletsConnected = 1000
const walletsConnected = new Set<string>()
let isEventListenerCreated = false

export function registerWalletAddress (walletAddress: unknown): boolean {
  if (typeof walletAddress !== 'string' || !walletAddressPattern.test(walletAddress)) {
    return false
  }
  const normalizedAddress = walletAddress.toLowerCase()
  walletsConnected.delete(normalizedAddress)
  if (walletsConnected.size >= maxWalletsConnected) {
    const oldestAddress = walletsConnected.values().next().value
    if (oldestAddress !== undefined) walletsConnected.delete(oldestAddress)
  }
  walletsConnected.add(normalizedAddress)
  return true
}

export function isWalletAddressConnected (walletAddress: string): boolean {
  return walletsConnected.has(walletAddress.toLowerCase())
}

export function connectedWalletsCount (): number {
  return walletsConnected.size
}

export function contractExploitListener () {
  return async (req: Request, res: Response) => {
    if (!registerWalletAddress(req.body?.walletAddress)) {
      res.status(400).json({ success: false, message: 'Invalid wallet address' })
      return
    }
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
          if (isWalletAddressConnected(exploiter)) {
            walletsConnected.delete(exploiter.toLowerCase())
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
