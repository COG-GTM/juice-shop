/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { retrieveChallengesWithCodeSnippet } from '../../routes/vulnCodeSnippet'
import { readFixes } from '../../routes/vulnCodeFixes'
import chai from 'chai'
import fs from 'graceful-fs'
import nodeFs from 'node:fs'
import sinon from 'sinon'
import sinonChai from 'sinon-chai'
const expect = chai.expect
chai.use(sinonChai)

describe('codingChallengeFixes', () => {
  let codingChallenges: string[]
  before(async () => {
    codingChallenges = await retrieveChallengesWithCodeSnippet()
  })

  it('should have a correct fix for each coding challenge', async () => {
    for (const challenge of codingChallenges) {
      const fixes = readFixes(challenge)
      expect(fixes.correct, `Coding challenge ${challenge} does not have a correct fix file`).to.be.greaterThan(-1)
    }
  })

  it('should have a total of three or more fix options for each coding challenge', async () => {
    for (const challenge of codingChallenges) {
      const fixes = readFixes(challenge)
      expect(fixes.fixes.length, `Coding challenge ${challenge} does not have enough fix option files`).to.be.greaterThanOrEqual(3)
    }
  })

  it('should return no fixes for unknown or partial challenge keys', () => {
    for (const key of ['doesNotExistChallenge', 'resetPasswordBenderChallenge_1', '', 'x'.repeat(10000)]) {
      const fixes = readFixes(key)
      expect(fixes.fixes).to.deep.equal([])
      expect(fixes.correct).to.equal(-1)
    }
  })

  it('should not read the fixes directory again for unknown keys', () => {
    readFixes('resetPasswordBenderChallenge')
    const readdirSpy = sinon.spy(nodeFs, 'readdirSync')
    try {
      for (let i = 0; i < 100; i++) {
        readFixes(`unknownChallenge${i}`)
      }
      expect(readdirSpy).to.have.callCount(0)
    } finally {
      readdirSpy.restore()
    }
  })

  it('should have an info YAML file for each coding challenge', async () => {
    for (const challenge of codingChallenges) {
      expect(fs.existsSync('./data/static/codefixes/' + challenge + '.info.yml'), `Coding challenge ${challenge} does not have an info YAML file`).to.equal(true)
    }
  })
})
