/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import Hashids from 'hashids/cjs'
import { type Challenge } from 'data/types'
import { challenges } from '../../data/datacache'
import { ChallengeModel } from '../../models/challenge'
import { restoreProgress, restoreProgressFindIt, restoreProgressFixIt } from '../../routes/restoreProgress'

const expect = chai.expect
chai.use(sinonChai)

const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
const encode = (salt: string, ids: number[]) => new Hashids(salt, 60, alphabet).encode(ids)

describe('restoreProgress', () => {
  let originalChallenges: Record<string, Challenge>
  let req: any
  let res: any

  const challenge = (id: number, key: string, solved = false) => ({ id, key, name: key, solved, save: () => ({ then () { } }) }) as unknown as Challenge

  before(() => {
    originalChallenges = { ...challenges } as unknown as Record<string, Challenge>
  })

  beforeEach(() => {
    for (const key of Object.keys(challenges)) {
      delete (challenges as Record<string, unknown>)[key]
    }
    challenges.scoreBoardChallenge = challenge(1, 'scoreBoardChallenge')
    challenges.adminSectionChallenge = challenge(2, 'adminSectionChallenge')
    challenges.continueCodeChallenge = challenge(3, 'continueCodeChallenge')
    res = { json: sinon.spy(), end: sinon.spy(), status: sinon.stub(), send: sinon.spy() }
    res.status.returns(res)
  })

  afterEach(() => {
    sinon.restore()
  })

  after(() => {
    for (const key of Object.keys(challenges)) {
      delete (challenges as Record<string, unknown>)[key]
    }
    Object.assign(challenges, originalChallenges)
  })

  describe('restoreProgress', () => {
    it('should restore all challenges contained in the continue code', () => {
      req = { params: { continueCode: encode('this is my salt', [1, 2]) } }

      restoreProgress()(req, res)

      expect(challenges.scoreBoardChallenge.solved).to.equal(true)
      expect(challenges.adminSectionChallenge.solved).to.equal(true)
      expect(challenges.continueCodeChallenge.solved).to.equal(false)
      expect(res.json).to.have.been.calledWith({ data: '2 solved challenges have been restored.' })
    })

    it('should solve "continueCodeChallenge" for a continue code containing the non-existent challenge id 999', () => {
      req = { params: { continueCode: encode('this is my salt', [999]) } }

      restoreProgress()(req, res)

      expect(challenges.continueCodeChallenge.solved).to.equal(true)
      expect(res.end).to.have.been.calledWith()
    })

    it('should reject continue code with invalid characters', () => {
      req = { params: { continueCode: 'not/a-valid code' } }

      restoreProgress()(req, res)

      expect(res.status).to.have.been.calledWith(404)
      expect(res.send).to.have.been.calledWith('Invalid continue code.')
    })

    it('should reject continue code that does not decode to any challenge id', () => {
      req = { params: { continueCode: 'abc' } }

      restoreProgress()(req, res)

      expect(res.status).to.have.been.calledWith(404)
      expect(res.send).to.have.been.calledWith('Invalid continue code.')
    })

    it('should not accept continue codes generated for "Find It" phase', () => {
      req = { params: { continueCode: encode('this is the salt for findIt challenges', [1]) } }

      restoreProgress()(req, res)

      expect(challenges.scoreBoardChallenge.solved).to.equal(false)
      expect(res.status).to.have.been.calledWith(404)
    })
  })

  describe('restoreProgressFindIt', () => {
    it('should restore "Find It" phase of all challenges contained in the continue code', async () => {
      const update = sinon.stub(ChallengeModel, 'update').resolves([1] as any)
      req = { params: { continueCode: encode('this is the salt for findIt challenges', [1, 2]) } }

      await restoreProgressFindIt()(req, res)

      expect(update).to.have.callCount(2)
      expect(update).to.have.been.calledWith({ codingChallengeStatus: 1 }, sinon.match({ where: sinon.match({ key: 'scoreBoardChallenge' }) }))
      expect(update).to.have.been.calledWith({ codingChallengeStatus: 1 }, sinon.match({ where: sinon.match({ key: 'adminSectionChallenge' }) }))
      expect(res.json).to.have.been.calledWith({ data: '2 solved challenges have been restored.' })
    })

    it('should reject continue code with invalid characters', async () => {
      req = { params: { continueCode: '../etc/passwd' } }

      await restoreProgressFindIt()(req, res)

      expect(res.status).to.have.been.calledWith(404)
      expect(res.send).to.have.been.calledWith('Invalid continue code.')
    })

    it('should reject continue code that does not decode to any challenge id', async () => {
      req = { params: { continueCode: 'abc' } }

      await restoreProgressFindIt()(req, res)

      expect(res.status).to.have.been.calledWith(404)
    })
  })

  describe('restoreProgressFixIt', () => {
    it('should restore "Fix It" phase of all challenges contained in the continue code', async () => {
      const update = sinon.stub(ChallengeModel, 'update').resolves([1] as any)
      req = { params: { continueCode: encode('yet another salt for the fixIt challenges', [2]) } }

      await restoreProgressFixIt()(req, res)

      expect(update).to.have.been.calledOnceWith({ codingChallengeStatus: 2 }, { where: { key: 'adminSectionChallenge' } })
      expect(res.json).to.have.been.calledWith({ data: '1 solved challenges have been restored.' })
    })

    it('should reject continue code with invalid characters', async () => {
      req = { params: { continueCode: '../etc/passwd' } }

      await restoreProgressFixIt()(req, res)

      expect(res.status).to.have.been.calledWith(404)
    })

    it('should reject continue code that does not decode to any challenge id', async () => {
      req = { params: { continueCode: 'abc' } }

      await restoreProgressFixIt()(req, res)

      expect(res.status).to.have.been.calledWith(404)
    })
  })
})
