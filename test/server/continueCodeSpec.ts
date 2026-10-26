/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import Hashids from 'hashids/cjs'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { ChallengeModel } from '../../models/challenge'
import { continueCode, continueCodeFindIt, continueCodeFixIt } from '../../routes/continueCode'

const expect = chai.expect
chai.use(sinonChai)

describe('continueCode', () => {
  const originalChallenges = { ...challenges }

  after(() => {
    for (const key of Object.keys(challenges)) {
      delete challenges[key]
    }
    Object.assign(challenges, originalChallenges)
  })

  let req: any
  let res: any

  beforeEach(() => {
    for (const key of Object.keys(challenges)) {
      delete challenges[key]
    }
    req = {}
    res = { json: sinon.spy() }
  })

  it('should be empty when no challenges are solved', () => {
    challenges.scoreBoardChallenge = { solved: false } as unknown as Challenge
    challenges.adminSectionChallenge = { solved: false } as unknown as Challenge

    continueCode()(req, res)
    expect(res.json).to.have.been.calledWith({ continueCode: undefined })
  })

  it('should be hashid value of IDs of solved challenges', () => {
    challenges.scoreBoardChallenge = { id: 1, solved: true } as unknown as Challenge
    challenges.adminSectionChallenge = { id: 2, solved: true } as unknown as Challenge
    challenges.continueCodeChallenge = { id: 3, solved: false } as unknown as Challenge

    continueCode()(req, res)
    expect(res.json).to.have.been.calledWith({ continueCode: 'yXjv6Z5jWJnzD6a3YvmwPRXK7roAyzHDde2Og19yEN84plqxkMBbLVQrDeoY' })
  })

  describe('continueCodeFindIt', () => {
    afterEach(() => {
      sinon.restore()
    })

    it('should be empty when no "Find It" phase is solved', async () => {
      sinon.stub(ChallengeModel, 'findAll').resolves([])

      await continueCodeFindIt()(req, res)
      expect(res.json).to.have.been.calledWith({ continueCode: undefined })
    })

    it('should be hashid value of IDs of challenges with solved "Find It" phase', async () => {
      const findAll = sinon.stub(ChallengeModel, 'findAll').resolves([{ id: 1 }, { id: 2 }] as any)

      await continueCodeFindIt()(req, res)
      expect(findAll).to.have.been.calledWith(sinon.match({ where: sinon.match.has('codingChallengeStatus') }))
      const hashids = new Hashids('this is the salt for findIt challenges', 60, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890')
      expect(hashids.decode(res.json.firstCall.args[0].continueCode)).to.deep.equal([1, 2])
    })
  })

  describe('continueCodeFixIt', () => {
    afterEach(() => {
      sinon.restore()
    })

    it('should be empty when no "Fix It" phase is solved', async () => {
      sinon.stub(ChallengeModel, 'findAll').resolves([])

      await continueCodeFixIt()(req, res)
      expect(res.json).to.have.been.calledWith({ continueCode: undefined })
    })

    it('should be hashid value of IDs of challenges with solved "Fix It" phase', async () => {
      sinon.stub(ChallengeModel, 'findAll').resolves([{ id: 1 }, { id: 2 }] as any)

      await continueCodeFixIt()(req, res)
      const hashids = new Hashids('yet another salt for the fixIt challenges', 60, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890')
      expect(hashids.decode(res.json.firstCall.args[0].continueCode)).to.deep.equal([1, 2])
    })
  })
})
