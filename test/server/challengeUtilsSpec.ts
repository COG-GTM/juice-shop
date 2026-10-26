/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import sinon from 'sinon'
import * as challengeUtils from '../../lib/challengeUtils'
import * as utils from '../../lib/utils'
import { challenges, notifications } from '../../data/datacache'
import { type Challenge } from 'data/types'

const expect = chai.expect

describe('challengeUtils', () => {
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

  describe('sendNotification', () => {
    const globalWithSocketIO = global as unknown as { io?: { emit: sinon.SinonSpy } }
    let previousIo: { emit: sinon.SinonSpy } | undefined
    const solvedChallenge = { key: 'scoreBoardChallenge', name: 'Score Board', description: 'Find the score board.', solved: true }

    beforeEach(() => {
      previousIo = globalWithSocketIO.io
      globalWithSocketIO.io = { emit: sinon.spy() }
      notifications.splice(0, notifications.length)
    })

    afterEach(() => {
      globalWithSocketIO.io = previousIo
      notifications.splice(0, notifications.length)
    })

    it('includes the CTF flag when a challenge is solved', () => {
      challengeUtils.sendNotification(solvedChallenge, false)
      const notification = globalWithSocketIO.io?.emit.firstCall.args[1]
      expect(notification.flag).to.equal(utils.ctfFlag('Score Board'))
      expect(notification.isRestore).to.equal(false)
    })

    it('does not broadcast or queue the CTF flag for restored challenges', () => {
      challengeUtils.sendNotification(solvedChallenge, true)
      expect(globalWithSocketIO.io?.emit).to.have.callCount(1)
      const notification = globalWithSocketIO.io?.emit.firstCall.args[1]
      expect(notification).to.not.have.property('flag')
      expect(notification.isRestore).to.equal(true)
      expect(notifications[0]).to.not.have.property('flag')
    })
  })
})
