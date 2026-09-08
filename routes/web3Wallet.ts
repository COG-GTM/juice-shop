import { type Request, type Response } from 'express'

import logger from '../lib/logger'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'
import { web3WalletABI } from '../data/static/contractABIs'

const web3WalletAddress = '0x413744D59d31AFDC2889aeE602636177805Bd7b0'
const MAX_WALLETS_CONNECTED = 1000
const WALLET_ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/
const walletsConnected = new Set<string>()
let isEventListenerCreated = false

function isValidWalletAddress (address: unknown): address is string {
  return typeof address === 'string' && WALLET_ADDRESS_PATTERN.test(address)
}

function rememberWallet (address: string) {
  const normalized = address.toLowerCase()
  walletsConnected.delete(normalized)
  walletsConnected.add(normalized)
  if (walletsConnected.size > MAX_WALLETS_CONNECTED) {
    const oldest = walletsConnected.values().next().value
    if (oldest !== undefined) walletsConnected.delete(oldest)
  }
}

export function contractExploitListener () {
  return async (req: Request, res: Response) => {
    const metamaskAddress = req.body.walletAddress
    if (isValidWalletAddress(metamaskAddress)) {
      rememberWallet(metamaskAddress)
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
          const exploiterAddress = exploiter.toLowerCase()
          if (walletsConnected.has(exploiterAddress)) {
            walletsConnected.delete(exploiterAddress)
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
