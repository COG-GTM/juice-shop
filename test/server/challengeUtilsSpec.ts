/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import * as challengeUtils from '../../lib/challengeUtils'
import { challenges } from '../../data/datacache'
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

  describe('notificationFor', () => {
    const notification = { key: 'scoreBoardChallenge', name: 'Score Board', challenge: 'Score Board (Find it)', flag: 'secret-flag', hidden: false, isRestore: false }

    it('never reveals the flag to anonymous viewers', () => {
      expect(challengeUtils.notificationFor(notification)).to.not.have.property('flag')
      expect(challengeUtils.notificationFor({ ...notification, solverId: 1 })).to.not.have.property('flag')
    })

    it('reveals the flag only to the solver of an attributed challenge', () => {
      expect(challengeUtils.notificationFor({ ...notification, solverId: 1 }, 1)).to.have.property('flag', 'secret-flag')
      expect(challengeUtils.notificationFor({ ...notification, solverId: 1 }, 2)).to.not.have.property('flag')
    })

    it('reveals the flag of an unattributed challenge to any authenticated viewer', () => {
      expect(challengeUtils.notificationFor(notification, 2)).to.have.property('flag', 'secret-flag')
    })

    it('never exposes the solver id', () => {
      expect(challengeUtils.notificationFor({ ...notification, solverId: 1 }, 1)).to.not.have.property('solverId')
      expect(challengeUtils.notificationFor({ ...notification, solverId: 1 })).to.deep.equal({ key: 'scoreBoardChallenge', name: 'Score Board', challenge: 'Score Board (Find it)', hidden: false, isRestore: false })
    })
  })
})
