import { type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { nftABI } from '../data/static/contractABIs'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'
import { ContractEventListener } from '../lib/contractEventListener'

const nftAddress = '0x41427790c94E7a592B17ad694eD9c06A02bb9C39'
const addressesMinted = new Set()

export const nftMintEventListener = new ContractEventListener('NFT Mint Listener', async (fail) => {
  const { WebSocketProvider, Contract } = await import('ethers')
  const provider = new WebSocketProvider(`wss://eth-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY ?? ''}`)
  const contract = new Contract(nftAddress, nftABI, provider as any)
  contract.on('NFTMinted', (minter: string) => {
    if (!addressesMinted.has(minter)) {
      addressesMinted.add(minter)
    }
  }).catch(fail)
  return provider as any
})

export function nftMintListener () {
  return async (req: Request, res: Response) => {
    try {
      await nftMintEventListener.ensureStarted()
      res.status(200).json({ success: true, message: 'Event Listener Created' })
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}

export function walletNFTVerify () {
  return (req: Request, res: Response) => {
    try {
      const metamaskAddress = req.body.walletAddress
      if (addressesMinted.has(metamaskAddress)) {
        addressesMinted.delete(metamaskAddress)
        challengeUtils.solveIf(challenges.nftMintChallenge, () => true)
        res.status(200).json({ success: true, message: 'Challenge successfully solved', status: challenges.nftMintChallenge })
      } else {
        res.status(200).json({ success: false, message: 'Wallet did not mint the NFT', status: challenges.nftMintChallenge })
      }
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
