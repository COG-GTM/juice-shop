/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import sinon from 'sinon'
import * as challengeUtils from '../../lib/challengeUtils'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import logger from '../../lib/logger'

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

    it('strips line breaks from the logged name of a non-existing challenge', () => {
      const warn = sinon.stub(logger, 'warn')
      try {
        challengeUtils.findChallengeByName('blubb\r\nwarn: Solved 6-star forgedChallenge\n')
        expect(warn.callCount).to.equal(1)
        expect(warn.firstCall.args).to.deep.equal(['Missing challenge with name: blubbwarn: Solved 6-star forgedChallenge'])
      } finally {
        warn.restore()
      }
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
})
