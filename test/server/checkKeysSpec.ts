/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { HDNodeWallet } from 'ethers'
import { type Challenge } from 'data/types'
import { challenges } from '../../data/datacache'
import { checkKeys, nftUnlocked } from '../../routes/checkKeys'

const expect = chai.expect
chai.use(sinonChai)

describe('checkKeys', () => {
  const originalChallenges = { ...challenges }

  after(() => {
    for (const key of Object.keys(challenges)) {
      delete challenges[key]
    }
    Object.assign(challenges, originalChallenges)
  })

  const wallet = HDNodeWallet.fromPhrase('purpose betray marriage blame crunch monitor spin slide donate sport lift clutch')
  let req: any
  let res: any
  let save: any

  beforeEach(() => {
    res = { json: sinon.spy(), status: sinon.stub() }
    res.status.returns(res)
    save = () => ({
      then () { }
    })
    challenges.nftUnlockChallenge = { solved: false, save } as unknown as Challenge
  })

  describe('checkKeys', () => {
    it('should solve "nftUnlockChallenge" for the private key of the wallet', async () => {
      req = { body: { privateKey: wallet.privateKey } }

      await checkKeys()(req, res)

      expect(challenges.nftUnlockChallenge.solved).to.equal(true)
      expect(res.status).to.have.been.calledWith(200)
      expect(res.json).to.have.been.calledWith(sinon.match({ success: true, message: 'Challenge successfully solved' }))
    })

    it('should give a hint when the wallet address is submitted', async () => {
      req = { body: { privateKey: wallet.address } }

      await checkKeys()(req, res)

      expect(challenges.nftUnlockChallenge.solved).to.equal(false)
      expect(res.status).to.have.been.calledWith(401)
      expect(res.json).to.have.been.calledWith(sinon.match({ success: false, message: 'Looks like you entered the public address of my ethereum wallet!' }))
    })

    it('should give a hint when the public key is submitted', async () => {
      req = { body: { privateKey: wallet.publicKey } }

      await checkKeys()(req, res)

      expect(res.status).to.have.been.calledWith(401)
      expect(res.json).to.have.been.calledWith(sinon.match({ success: false, message: 'Looks like you entered the public key of my ethereum wallet!' }))
    })

    it('should reject any other key', async () => {
      req = { body: { privateKey: '0x1234' } }

      await checkKeys()(req, res)

      expect(challenges.nftUnlockChallenge.solved).to.equal(false)
      expect(res.status).to.have.been.calledWith(401)
      expect(res.json).to.have.been.calledWith(sinon.match({ success: false, message: 'Looks like you entered a non-Ethereum private key to access me.' }))
    })

    it('should respond with 500 when request has no body', async () => {
      req = {}

      await checkKeys()(req, res)

      expect(res.status).to.have.been.calledWith(500)
    })
  })

  describe('nftUnlocked', () => {
    it('should report solved status of "nftUnlockChallenge"', () => {
      challenges.nftUnlockChallenge.solved = true

      nftUnlocked()({} as any, res)

      expect(res.status).to.have.been.calledWith(200)
      expect(res.json).to.have.been.calledWith({ status: true })
    })
  })
})
