/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import sinon from 'sinon'
import * as challengeUtils from '../../lib/challengeUtils'
import { challenges, notifications } from '../../data/datacache'
import { type Challenge } from 'data/types'

const expect = chai.expect
const globalWithSocketIO = global as typeof globalThis & { io: any }

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

  describe('notifications', () => {
    const solvedChallenge = { key: 'scoreBoardChallenge', name: 'Score Board', description: 'Find the score board.', solved: true }
    let originalIo: any
    let broadcast: sinon.SinonSpy
    let toSocket: sinon.SinonSpy
    let to: sinon.SinonStub

    beforeEach(() => {
      notifications.length = 0
      originalIo = globalWithSocketIO.io
      broadcast = sinon.spy()
      toSocket = sinon.spy()
      to = sinon.stub().returns({ emit: toSocket })
      globalWithSocketIO.io = { emit: broadcast, to }
    })

    afterEach(() => {
      globalWithSocketIO.io = originalIo
      notifications.length = 0
    })

    it('queues at most one notification per challenge however often it is sent', () => {
      for (let i = 0; i < 100; i++) {
        challengeUtils.sendNotification(solvedChallenge, true)
      }

      expect(notifications.length).to.equal(1)
      expect(notifications[0].key).to.equal('scoreBoardChallenge')
    })

    it('broadcasts a newly solved challenge only once', () => {
      challengeUtils.sendNotification(solvedChallenge, false)
      challengeUtils.sendNotification(solvedChallenge, false)

      expect(broadcast.callCount).to.equal(1)
      expect(broadcast.firstCall.args[0]).to.equal('challenge solved')
    })

    it('repeats a notification only to the requesting socket without queueing it', () => {
      challengeUtils.repeatNotification(solvedChallenge, 'requester-socket')

      expect(to.callCount).to.equal(1)
      expect(to.firstCall.args[0]).to.equal('requester-socket')
      expect(toSocket.callCount).to.equal(1)
      expect(toSocket.firstCall.args[0]).to.equal('challenge solved')
      expect(toSocket.firstCall.args[1].isRestore).to.equal(true)
      expect(broadcast.callCount).to.equal(0)
      expect(notifications.length).to.equal(0)
    })

    it('does not repeat notifications for unsolved challenges', () => {
      const unsolvedChallenge = { ...solvedChallenge, solved: false }
      challengeUtils.repeatNotification(unsolvedChallenge, 'requester-socket')

      expect(to.callCount).to.equal(0)
      expect(broadcast.callCount).to.equal(0)
    })
  })
})
