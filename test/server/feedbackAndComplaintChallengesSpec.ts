/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import config from 'config'
import { challenges } from '../../data/datacache'
import type { Challenge } from 'data/types'
import type { Product as ProductConfig } from '../../lib/config.types'
import { solveFiveStarFeedbackChallenge, solveTextChallenges } from '../../lib/feedbackAndComplaintChallenges'
const expect = chai.expect

describe('feedbackAndComplaintChallenges', () => {
  const save = () => ({ then () { } })
  const keys = ['knownVulnerableComponentChallenge', 'weirdCryptoChallenge', 'typosquattingNpmChallenge', 'typosquattingAngularChallenge',
    'hiddenImageChallenge', 'supplyChainAttackChallenge', 'dlpPastebinDataLeakChallenge', 'csafChallenge', 'leakedApiKeyChallenge', 'feedbackChallenge'] as const

  beforeEach(() => {
    for (const key of keys) {
      challenges[key] = { solved: false, save } as unknown as Challenge
    }
  })

  const solvedChallenges = () => keys.filter(key => challenges[key].solved)

  describe('solveTextChallenges', () => {
    const cases: Array<[string, string, typeof keys[number]]> = [
      ['vulnerable sanitize-html version', 'Please upgrade sanitize-html 1.4.2!', 'knownVulnerableComponentChallenge'],
      ['vulnerable express-jwt version', 'express-jwt 0.1.3 is outdated', 'knownVulnerableComponentChallenge'],
      ['weird crypto', 'Why do you still use MD5?', 'weirdCryptoChallenge'],
      ['typosquatted npm package', 'epilogue-js is a typosquat', 'typosquattingNpmChallenge'],
      ['typosquatted angular package', 'ngy-cookie is a typosquat', 'typosquattingAngularChallenge'],
      ['hidden image character', 'Pickle Rick is hiding there', 'hiddenImageChallenge'],
      ['eslint-scope issue', 'https://github.com/eslint/eslint-scope/issues/39', 'supplyChainAttackChallenge'],
      ['csaf hash', `hash: ${config.get<string>('challenges.csafHashValue')}`, 'csafChallenge'],
      ['leaked API key', 'key 6PPi37DBxP4lDwlriuaxP15HaDJpsUXY5TspVmie', 'leakedApiKeyChallenge']
    ]

    for (const [description, text, key] of cases) {
      it(`solves only ${key} for text mentioning ${description}`, () => {
        solveTextChallenges(text)
        expect(solvedChallenges()).to.deep.equal([key])
      })
    }

    it('requires all pastebin leak keywords for dlpPastebinDataLeakChallenge', () => {
      const keywords = config.get<ProductConfig[]>('products').flatMap(product => product.keywordsForPastebinDataLeakChallenge ?? [])
      expect(keywords.length).to.be.greaterThan(1)

      solveTextChallenges(keywords[0])
      expect(challenges.dlpPastebinDataLeakChallenge.solved).to.equal(false)

      solveTextChallenges(keywords.join(', ').toUpperCase())
      expect(challenges.dlpPastebinDataLeakChallenge.solved).to.equal(true)
    })

    it('requires product and version together for knownVulnerableComponentChallenge', () => {
      solveTextChallenges('sanitize-html is great, so is express-jwt')
      expect(solvedChallenges()).to.deep.equal([])
    })

    it('solves nothing for ordinary or non-string text', () => {
      solveTextChallenges('Great juice, fast delivery!')
      solveTextChallenges(undefined)
      solveTextChallenges({ comment: 'pickle rick' })
      expect(solvedChallenges()).to.deep.equal([])
    })

    it('does not throw when a challenge cannot be solved', () => {
      challenges.hiddenImageChallenge = { solved: false, save () { throw new Error('db down') } } as unknown as Challenge
      expect(() => { solveTextChallenges('pickle rick and md5') }).to.not.throw()
      expect(challenges.weirdCryptoChallenge.solved).to.equal(true)
    })
  })

  describe('solveFiveStarFeedbackChallenge', () => {
    it('solves feedbackChallenge when no five-star feedback is left', async () => {
      await solveFiveStarFeedbackChallenge(async () => 0)
      expect(challenges.feedbackChallenge.solved).to.equal(true)
    })

    it('does not solve feedbackChallenge while five-star feedback exists', async () => {
      await solveFiveStarFeedbackChallenge(async () => 2)
      expect(challenges.feedbackChallenge.solved).to.equal(false)
    })

    it('does not query once feedbackChallenge is solved', async () => {
      challenges.feedbackChallenge.solved = true
      let queried = false
      await solveFiveStarFeedbackChallenge(async () => { queried = true; return 0 })
      expect(queried).to.equal(false)
    })

    it('resolves instead of rejecting when the query fails', async () => {
      await solveFiveStarFeedbackChallenge(async () => { throw new Error('SQLITE_BUSY') })
      expect(challenges.feedbackChallenge.solved).to.equal(false)
    })
  })
})
