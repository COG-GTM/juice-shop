import config from 'config'
import { type Request, type Response } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

export function checkKeys () {
  return async (req: Request, res: Response) => {
    try {
      const { Wallet, computeAddress, getAddress } = await import('ethers')
      const walletAddress = getAddress(config.get<string>('challenges.nftWalletAddress'))
      const submittedKey = typeof req.body.privateKey === 'string' ? req.body.privateKey : ''

      const addressOf = (derive: (key: string) => string) => {
        try {
          return derive(submittedKey)
        } catch {
          return undefined
        }
      }
      const isPrivateKey = addressOf((key) => new Wallet(key).address) === walletAddress
      const isPublicKey = addressOf((key) => computeAddress(key)) === walletAddress
      const isAddress = addressOf((key) => getAddress(key)) === walletAddress

      challengeUtils.solveIf(challenges.nftUnlockChallenge, () => isPrivateKey)
      if (isPrivateKey) {
        res.status(200).json({ success: true, message: 'Challenge successfully solved', status: challenges.nftUnlockChallenge })
      } else {
        if (isAddress) {
          res.status(401).json({ success: false, message: 'Looks like you entered the public address of my ethereum wallet!', status: challenges.nftUnlockChallenge })
        } else if (isPublicKey) {
          res.status(401).json({ success: false, message: 'Looks like you entered the public key of my ethereum wallet!', status: challenges.nftUnlockChallenge })
        } else {
          res.status(401).json({ success: false, message: 'Looks like you entered a non-Ethereum private key to access me.', status: challenges.nftUnlockChallenge })
        }
      }
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
export function nftUnlocked () {
  return (req: Request, res: Response) => {
    try {
      res.status(200).json({ status: challenges.nftUnlockChallenge.solved })
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
