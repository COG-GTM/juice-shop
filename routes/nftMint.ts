import { type Request, type Response } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { nftABI } from '../data/static/contractABIs'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'
import { addBounded, createContractListener } from '../lib/contractListener'

const nftAddress = '0x41427790c94E7a592B17ad694eD9c06A02bb9C39'
const MAX_TRACKED_MINTERS = 1000
const addressesMinted = new Set()

const ensureListening = createContractListener({
  name: 'NFT Mint Listener',
  address: nftAddress,
  abi: nftABI,
  event: 'NFTMinted',
  onEvent: (minter: string) => {
    addBounded(addressesMinted, minter, MAX_TRACKED_MINTERS)
  }
})

export function nftMintListener () {
  return async (req: Request, res: Response) => {
    try {
      await ensureListening()
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
