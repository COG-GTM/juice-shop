import { type Request, type Response } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import crypto from 'node:crypto'

const nftWalletAddress = '0x8343d2eb2B13A2495De435a1b15e85b98115Ce05'
const nftWalletPublicKey = '0x02c7a2a93289c9fbda5990bac6596993e9bb0a8d3f178175a80b7cfd983983f506'
const nftWalletPrivateKeySha256 = Buffer.from('69623bda028d67ac20b693094865c91c4c819d998983feda53b468b3ab9b0c60', 'hex')

function isNftWalletPrivateKey (candidate: string) {
  const digest = crypto.createHash('sha256').update(candidate).digest()
  return crypto.timingSafeEqual(digest, nftWalletPrivateKeySha256)
}

export function checkKeys () {
  return async (req: Request, res: Response) => {
    try {
      const submittedKey = typeof req.body.privateKey === 'string' ? req.body.privateKey : ''
      const isPrivateKey = isNftWalletPrivateKey(submittedKey)
      challengeUtils.solveIf(challenges.nftUnlockChallenge, () => {
        return isPrivateKey
      })
      if (isPrivateKey) {
        res.status(200).json({ success: true, message: 'Challenge successfully solved', status: challenges.nftUnlockChallenge })
      } else {
        if (submittedKey === nftWalletAddress) {
          res.status(401).json({ success: false, message: 'Looks like you entered the public address of my ethereum wallet!', status: challenges.nftUnlockChallenge })
        } else if (submittedKey === nftWalletPublicKey) {
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
