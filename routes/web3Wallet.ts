import { type Request, type Response } from 'express'

import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'
import { web3WalletABI } from '../data/static/contractABIs'
import { addBounded, createContractListener } from '../lib/contractListener'

const web3WalletAddress = '0x413744D59d31AFDC2889aeE602636177805Bd7b0'
const MAX_TRACKED_WALLETS = 1000
const walletsConnected = new Set<string>()

const ensureListening = createContractListener({
  name: 'Contract Exploit Listener',
  address: web3WalletAddress,
  abi: web3WalletABI,
  event: 'ContractExploited',
  onEvent: async (exploiter: string) => {
    const { getAddress, isAddress } = await import('ethers')
    if (!isAddress(exploiter)) return
    const normalized = getAddress(exploiter)
    if (walletsConnected.has(normalized)) {
      walletsConnected.delete(normalized)
      challengeUtils.solveIf(challenges.web3WalletChallenge, () => true)
    }
  }
})

export function contractExploitListener () {
  return async (req: Request, res: Response) => {
    const { getAddress, isAddress } = await import('ethers')
    const metamaskAddress = req.body?.walletAddress
    if (typeof metamaskAddress !== 'string' || !isAddress(metamaskAddress)) {
      res.status(400).json({ success: false, message: 'Invalid wallet address' })
      return
    }
    addBounded(walletsConnected, getAddress(metamaskAddress), MAX_TRACKED_WALLETS)
    try {
      await ensureListening()
      res.status(200).json({ success: true, message: 'Event Listener Created' })
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
