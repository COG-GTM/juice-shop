/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import * as challengeUtils from '../../lib/challengeUtils'
import { challenges, notifications } from '../../data/datacache'
import { type Challenge } from 'data/types'

const expect = chai.expect

const globalWithSocketIO = global as typeof globalThis & { io?: any }

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
    const solvedChallenge = { key: 'scoreBoardChallenge', name: 'scoreBoardChallenge', description: 'Find the carefully hidden Score Board page.', solved: true }
    let emitted: any[]
    let previousIo: any

    beforeEach(() => {
      emitted = []
      previousIo = globalWithSocketIO.io
      globalWithSocketIO.io = { emit: (_event: string, notification: any) => emitted.push(notification) }
      notifications.length = 0
    })

    afterEach(() => {
      globalWithSocketIO.io = previousIo
      notifications.length = 0
    })

    it('emits and caches a notification with CTF flag by default', () => {
      challengeUtils.sendNotification(solvedChallenge, false)

      expect(emitted).to.have.lengthOf(1)
      expect(emitted[0].flag).to.be.a('string')
      expect(notifications).to.have.lengthOf(1)
    })

    it('emits a notification without CTF flag and leaves the cache untouched when flag is excluded', () => {
      challengeUtils.sendNotification(solvedChallenge, true, false)

      expect(emitted).to.have.lengthOf(1)
      expect(emitted[0].flag).to.equal(undefined)
      expect(notifications).to.have.lengthOf(0)
    })
  })
})
