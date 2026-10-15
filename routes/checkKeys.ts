import crypto from 'node:crypto'
import config from 'config'
import { type Request, type Response } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

const walletAddress = '0x8343d2eb2B13A2495De435a1b15e85b98115Ce05'
const walletPublicKey = '0x02c7a2a93289c9fbda5990bac6596993e9bb0a8d3f178175a80b7cfd983983f506'

function isWalletPrivateKey (candidate: unknown) {
  const expectedHash = Buffer.from(config.get<string>('challenges.nftUnlockPrivateKeyHash'), 'hex')
  if (typeof candidate !== 'string' || expectedHash.length === 0) return false
  const candidateHash = crypto.createHash('sha256').update(candidate).digest()
  return candidateHash.length === expectedHash.length && crypto.timingSafeEqual(candidateHash, expectedHash)
}

export function checkKeys () {
  return async (req: Request, res: Response) => {
    try {
      const keyMatches = isWalletPrivateKey(req.body.privateKey)
      challengeUtils.solveIf(challenges.nftUnlockChallenge, () => keyMatches)
      if (keyMatches) {
        res.status(200).json({ success: true, message: 'Challenge successfully solved', status: challenges.nftUnlockChallenge })
      } else {
        if (req.body.privateKey === walletAddress) {
          res.status(401).json({ success: false, message: 'Looks like you entered the public address of my ethereum wallet!', status: challenges.nftUnlockChallenge })
        } else if (req.body.privateKey === walletPublicKey) {
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
