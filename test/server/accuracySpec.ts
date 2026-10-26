/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { type ChallengeKey } from 'models/challenge'
import * as accuracy from '../../lib/accuracy'

const expect = chai.expect

describe('accuracy', () => {
  describe('Find It phase', () => {
    it('should report 0 attempts for a challenge without any verdict', () => {
      expect(accuracy.getFindItAttempts('accuracySpecUntouched' as ChallengeKey)).to.equal(0)
    })

    it('should have full accuracy when solved on first attempt', () => {
      const key = 'accuracySpecFindFirst' as ChallengeKey
      accuracy.storeFindItVerdict(key, true)

      expect(accuracy.getFindItAttempts(key)).to.equal(1)
      expect(accuracy.calculateFindItAccuracy(key)).to.equal(1)
    })

    it('should have accuracy of 1/attempts when solved after failed attempts', () => {
      const key = 'accuracySpecFindThird' as ChallengeKey
      accuracy.storeFindItVerdict(key, false)
      accuracy.storeFindItVerdict(key, false)
      accuracy.storeFindItVerdict(key, true)

      expect(accuracy.getFindItAttempts(key)).to.equal(3)
      expect(accuracy.calculateFindItAccuracy(key)).to.equal(1 / 3)
    })

    it('should ignore verdicts submitted after the challenge was solved', () => {
      const key = 'accuracySpecFindAfterSolve' as ChallengeKey
      accuracy.storeFindItVerdict(key, false)
      accuracy.storeFindItVerdict(key, true)
      accuracy.storeFindItVerdict(key, false)
      accuracy.storeFindItVerdict(key, true)

      expect(accuracy.getFindItAttempts(key)).to.equal(2)
      expect(accuracy.calculateFindItAccuracy(key)).to.equal(0.5)
    })

    it('should have zero accuracy while not yet solved', () => {
      const key = 'accuracySpecFindUnsolved' as ChallengeKey
      accuracy.storeFindItVerdict(key, false)

      expect(accuracy.calculateFindItAccuracy(key)).to.equal(0)
    })

    it('should calculate total accuracy across all solved challenges', () => {
      const total = accuracy.totalFindItAccuracy()

      expect(total).to.be.greaterThan(0)
      expect(total).to.be.at.most(1)
    })
  })

  describe('Fix It phase', () => {
    it('should track attempts independently from Find It phase', () => {
      const key = 'accuracySpecFixIndependent' as ChallengeKey
      accuracy.storeFindItVerdict(key, true)
      accuracy.storeFixItVerdict(key, false)
      accuracy.storeFixItVerdict(key, false)
      accuracy.storeFixItVerdict(key, false)
      accuracy.storeFixItVerdict(key, true)

      expect(accuracy.calculateFindItAccuracy(key)).to.equal(1)
      expect(accuracy.calculateFixItAccuracy(key)).to.equal(0.25)
    })

    it('should have zero accuracy while not yet solved', () => {
      const key = 'accuracySpecFixUnsolved' as ChallengeKey
      accuracy.storeFixItVerdict(key, false)

      expect(accuracy.calculateFixItAccuracy(key)).to.equal(0)
    })

    it('should calculate total accuracy across all solved challenges', () => {
      const total = accuracy.totalFixItAccuracy()

      expect(total).to.be.greaterThan(0)
      expect(total).to.be.at.most(1)
    })
  })
})
