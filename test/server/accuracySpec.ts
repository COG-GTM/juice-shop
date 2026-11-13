/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import * as accuracy from '../../lib/accuracy'
import { type ChallengeKey } from 'models/challenge'
const expect = chai.expect

describe('accuracy', () => {
  it('should count failed find-it attempts per challenge', () => {
    accuracy.storeFindItVerdict('scoreBoardChallenge', false)
    accuracy.storeFindItVerdict('scoreBoardChallenge', false)
    expect(accuracy.getFindItAttempts('scoreBoardChallenge')).to.equal(2)
  })

  it('should calculate accuracy from attempts until solved', () => {
    accuracy.storeFixItVerdict('loginAdminChallenge', false)
    accuracy.storeFixItVerdict('loginAdminChallenge', true)
    accuracy.storeFixItVerdict('loginAdminChallenge', false)
    expect(accuracy.calculateFixItAccuracy('loginAdminChallenge')).to.equal(0.5)
  })

  it('should not write to Object.prototype for prototype property names', () => {
    for (const key of ['__proto__', 'constructor', 'prototype', 'hasOwnProperty']) {
      accuracy.storeFindItVerdict(key as ChallengeKey, true)
    }
    expect(({} as any)['find it']).to.equal(undefined)
    expect(({} as any).attempts).to.equal(undefined)
    expect(accuracy.getFindItAttempts('__proto__' as ChallengeKey)).to.equal(1)
    expect(accuracy.getFindItAttempts('toString' as ChallengeKey)).to.equal(0)
  })

  it('should ignore non-string challenge keys', () => {
    accuracy.storeFindItVerdict(['nullByteChallenge'] as unknown as ChallengeKey, false)
    expect(accuracy.getFindItAttempts('nullByteChallenge')).to.equal(0)
  })
})
