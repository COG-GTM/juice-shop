/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
const expect = chai.expect

describe('accuracy', () => {
  let accuracy: any

  beforeEach(() => {
    delete require.cache[require.resolve('../../lib/accuracy')]
    accuracy = require('../../lib/accuracy')
  })

  afterEach(() => {
    delete (Object.prototype as any)['find it']
    delete (Object.prototype as any)['fix it']
  })

  it('should count failed attempts per challenge', () => {
    accuracy.storeFindItVerdict('restfulXssChallenge', false)
    accuracy.storeFindItVerdict('restfulXssChallenge', false)
    accuracy.storeFindItVerdict('restfulXssChallenge', true)

    expect(accuracy.getFindItAttempts('restfulXssChallenge')).to.equal(3)
    expect(accuracy.calculateFindItAccuracy('restfulXssChallenge')).to.equal(1 / 3)
  })

  it('should return 0 attempts for unknown challenges', () => {
    expect(accuracy.getFindItAttempts('unknownChallenge')).to.equal(0)
  })

  for (const key of ['__proto__', 'constructor', 'prototype']) {
    it(`should not pollute Object.prototype when storing a "Find It" verdict for key "${key}"`, () => {
      expect(() => accuracy.storeFindItVerdict(key, true)).to.not.throw()

      expect(({} as any)['find it']).to.equal(undefined)
      expect(accuracy.getFindItAttempts(key)).to.equal(1)
    })

    it(`should not pollute Object.prototype when storing a "Fix It" verdict for key "${key}"`, () => {
      expect(() => accuracy.storeFixItVerdict(key, true)).to.not.throw()

      expect(({} as any)['fix it']).to.equal(undefined)
      expect(accuracy.calculateFixItAccuracy(key)).to.equal(1)
    })
  }

  it('should calculate total accuracy only over solved challenges', () => {
    accuracy.storeFixItVerdict('a', false)
    accuracy.storeFixItVerdict('a', true)
    accuracy.storeFixItVerdict('b', true)
    accuracy.storeFixItVerdict('c', false)

    expect(accuracy.totalFixItAccuracy()).to.equal((1 / 2 + 1) / 2)
  })
})
