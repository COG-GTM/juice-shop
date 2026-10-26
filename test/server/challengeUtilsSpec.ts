/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import * as challengeUtils from '../../lib/challengeUtils'
import { challenges, notifications } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { ChallengeModel } from '../../models/challenge'

const expect = chai.expect
chai.use(sinonChai)

const globalWithSocketIO = global as typeof globalThis & { io: any }

describe('challengeUtils', () => {
  const originalChallenges = { ...challenges }

  after(() => {
    for (const key of Object.keys(challenges)) {
      delete challenges[key]
    }
    Object.assign(challenges, originalChallenges)
  })

  beforeEach(() => {
    challenges.scoreBoardChallenge = { id: 42, name: 'scoreBoardChallenge' } as unknown as Challenge
  })

  describe('findChallengeByName', () => {
    it('returns undefined for non-existing challenge', () => {
      expect(challengeUtils.findChallengeByName('blubbChallenge')).to.equal(undefined)
    })

    it('returns existing challenge', () => {
      expect(challengeUtils.findChallengeByName('scoreBoardChallenge')).to.deep.equal({ id: 42, name: 'scoreBoardChallenge' })
    })
  })

  describe('findChallengeById', () => {
    it('returns undefined for non-existing challenge', () => {
      expect(challengeUtils.findChallengeById(43)).to.equal(undefined)
    })

    it('returns existing challenge', () => {
      expect(challengeUtils.findChallengeById(42)).to.deep.equal({ id: 42, name: 'scoreBoardChallenge' })
    })
  })

  describe('notSolved', () => {
    it('returns true for unsolved challenge', () => {
      expect(challengeUtils.notSolved({ solved: false })).to.equal(true)
    })

    it('returns false for solved challenge', () => {
      expect(challengeUtils.notSolved({ solved: true })).to.equal(false)
    })

    it('returns falsy value for missing challenge', () => {
      expect(challengeUtils.notSolved(undefined)).to.equal(undefined)
    })
  })

  describe('solve', () => {
    it('marks challenge as solved and persists it', () => {
      const challenge = { solved: false, save: sinon.stub().returns({ then () { } }) }

      challengeUtils.solve(challenge)

      expect(challenge.solved).to.equal(true)
      expect(challenge.save).to.have.callCount(1)
    })
  })

  describe('solveIf', () => {
    let challenge: any

    beforeEach(() => {
      challenge = { solved: false, save: sinon.stub().returns({ then () { } }) }
    })

    it('solves unsolved challenge when criteria is met', () => {
      challengeUtils.solveIf(challenge, () => true)

      expect(challenge.solved).to.equal(true)
    })

    it('does not solve challenge when criteria is not met', () => {
      challengeUtils.solveIf(challenge, () => false)

      expect(challenge.solved).to.equal(false)
      expect(challenge.save).to.have.not.been.calledWith(sinon.match.any)
    })

    it('does not evaluate criteria for already solved challenge', () => {
      const criteria = sinon.stub().returns(true)
      challenge.solved = true

      challengeUtils.solveIf(challenge, criteria)

      expect(criteria).to.have.not.been.calledWith(sinon.match.any)
      expect(challenge.save).to.have.not.been.calledWith(sinon.match.any)
    })
  })

  describe('notifications', () => {
    let originalIo: any

    beforeEach(() => {
      originalIo = globalWithSocketIO.io
      globalWithSocketIO.io = { emit: sinon.spy() }
      notifications.length = 0
    })

    afterEach(() => {
      globalWithSocketIO.io = originalIo
      notifications.length = 0
    })

    describe('sendNotification', () => {
      const solvedChallenge = { key: 'scoreBoardChallenge', name: 'Score Board', description: 'Find the carefully hidden <em>Score Board</em> page.', solved: true }

      it('emits notification with sanitized description for solved challenge', () => {
        challengeUtils.sendNotification(solvedChallenge, false)

        expect(globalWithSocketIO.io.emit).to.have.been.calledWith('challenge solved', sinon.match({
          key: 'scoreBoardChallenge',
          name: 'Score Board',
          challenge: 'Score Board (Find the carefully hidden Score Board page.)',
          flag: sinon.match.string,
          isRestore: false
        }))
        expect(notifications).to.have.lengthOf(1)
      })

      it('does not emit the same notification twice', () => {
        challengeUtils.sendNotification(solvedChallenge, false)
        challengeUtils.sendNotification(solvedChallenge, false)

        expect(globalWithSocketIO.io.emit).to.have.callCount(1)
        expect(notifications).to.have.lengthOf(2)
      })

      it('always emits notifications for restored challenges', () => {
        challengeUtils.sendNotification(solvedChallenge, false)
        challengeUtils.sendNotification(solvedChallenge, true)

        expect(globalWithSocketIO.io.emit).to.have.callCount(2)
        expect(globalWithSocketIO.io.emit.secondCall).to.have.been.calledWith('challenge solved', sinon.match({ isRestore: true }))
      })

      it('ignores unsolved challenges', () => {
        challengeUtils.sendNotification({ ...solvedChallenge, solved: false } as any, false)

        expect(globalWithSocketIO.io.emit).to.have.not.been.calledWith(sinon.match.any)
        expect(notifications).to.have.lengthOf(0)
      })

      it('flags notification of challenge with coding challenge', () => {
        challenges.scoreBoardChallenge = { ...solvedChallenge, hasCodingChallenge: true } as unknown as Challenge

        challengeUtils.sendNotification(solvedChallenge, false)

        expect(notifications[0].codingChallenge).to.equal(true)
      })

      it('stores notification without emitting when no socket is available', () => {
        globalWithSocketIO.io = undefined

        challengeUtils.sendNotification(solvedChallenge, false)

        expect(notifications).to.have.lengthOf(1)
      })
    })

    describe('sendCodingChallengeNotification', () => {
      it('emits notification for solved "Find It" phase', () => {
        challengeUtils.sendCodingChallengeNotification({ key: 'scoreBoardChallenge', codingChallengeStatus: 1 })

        expect(globalWithSocketIO.io.emit).to.have.been.calledWith('code challenge solved', { key: 'scoreBoardChallenge', codingChallengeStatus: 1 })
      })

      it('emits notification for solved "Fix It" phase', () => {
        challengeUtils.sendCodingChallengeNotification({ key: 'scoreBoardChallenge', codingChallengeStatus: 2 })

        expect(globalWithSocketIO.io.emit).to.have.been.calledWith('code challenge solved', { key: 'scoreBoardChallenge', codingChallengeStatus: 2 })
      })

      it('does not emit notification for unsolved coding challenge', () => {
        challengeUtils.sendCodingChallengeNotification({ key: 'scoreBoardChallenge', codingChallengeStatus: 0 })

        expect(globalWithSocketIO.io.emit).to.have.not.been.calledWith(sinon.match.any)
      })
    })

    describe('solveFindIt', () => {
      afterEach(() => {
        sinon.restore()
      })

      it('only updates status when restoring', async () => {
        const update = sinon.stub(ChallengeModel, 'update').resolves([1] as any)

        await challengeUtils.solveFindIt('scoreBoardChallenge', true)

        expect(update).to.have.been.calledWith({ codingChallengeStatus: 1 }, sinon.match({ where: sinon.match({ key: 'scoreBoardChallenge' }) }))
        expect(globalWithSocketIO.io.emit).to.have.not.been.calledWith(sinon.match.any)
      })

      it('updates status and notifies about solved "Find It" phase', async () => {
        challenges.loginJimChallenge = { key: 'loginJimChallenge', name: 'Login Jim' } as unknown as Challenge
        sinon.stub(ChallengeModel, 'update').resolves([1] as any)

        await challengeUtils.solveFindIt('loginJimChallenge')

        expect(globalWithSocketIO.io.emit).to.have.been.calledWith('code challenge solved', { key: 'loginJimChallenge', codingChallengeStatus: 1 })
      })
    })

    describe('solveFixIt', () => {
      afterEach(() => {
        sinon.restore()
      })

      it('only updates status when restoring', async () => {
        const update = sinon.stub(ChallengeModel, 'update').resolves([1] as any)

        await challengeUtils.solveFixIt('scoreBoardChallenge', true)

        expect(update).to.have.been.calledWith({ codingChallengeStatus: 2 }, { where: { key: 'scoreBoardChallenge' } })
        expect(globalWithSocketIO.io.emit).to.have.not.been.calledWith(sinon.match.any)
      })

      it('updates status and notifies about solved "Fix It" phase', async () => {
        challenges.loginJimChallenge = { key: 'loginJimChallenge', name: 'Login Jim' } as unknown as Challenge
        sinon.stub(ChallengeModel, 'update').resolves([1] as any)

        await challengeUtils.solveFixIt('loginJimChallenge')

        expect(globalWithSocketIO.io.emit).to.have.been.calledWith('code challenge solved', { key: 'loginJimChallenge', codingChallengeStatus: 2 })
      })
    })
  })
})
