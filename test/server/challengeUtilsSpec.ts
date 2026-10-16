/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import * as challengeUtils from '../../lib/challengeUtils'
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
    beforeEach(() => {
      notifications.length = 0
    })

    it('queues one notification per solved challenge', () => {
      challengeUtils.sendNotification({ key: 'scoreBoardChallenge', name: 'Score Board', description: 'Find the score board.', solved: true } as any, false)
      challengeUtils.sendNotification({ key: 'adminSectionChallenge', name: 'Admin Section', description: 'Find the admin section.', solved: true } as any, false)

      expect(notifications.map(({ key }) => key)).to.deep.equal(['scoreBoardChallenge', 'adminSectionChallenge'])
    })

    it('replaces instead of appending repeated notifications for the same challenge', () => {
      const challenge = { key: 'scoreBoardChallenge', name: 'Score Board', description: 'Find the score board.', solved: true } as any
      for (let i = 0; i < 100; i++) {
        challengeUtils.sendNotification(challenge, true)
      }

      expect(notifications).to.have.lengthOf(1)
      expect(notifications[0].key).to.equal('scoreBoardChallenge')
      expect(notifications[0].isRestore).to.equal(true)
    })

    it('does not queue notifications for unsolved challenges', () => {
      challengeUtils.sendNotification({ key: 'scoreBoardChallenge', name: 'Score Board', description: 'Find the score board.', solved: false } as any, false)

      expect(notifications).to.have.lengthOf(0)
    })
  })
})
