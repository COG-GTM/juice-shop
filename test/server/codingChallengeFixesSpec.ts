/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { retrieveChallengesWithCodeSnippet } from '../../routes/vulnCodeSnippet'
import { readFixes } from '../../routes/vulnCodeFixes'
import chai from 'chai'
import fs from 'graceful-fs'
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

  it('should have an info YAML file for each coding challenge', async () => {
    for (const challenge of codingChallenges) {
      expect(fs.existsSync('./data/static/codefixes/' + challenge + '.info.yml'), `Coding challenge ${challenge} does not have an info YAML file`).to.equal(true)
    }
  })

  it('should cache fixes of an existing coding challenge', () => {
    expect(readFixes(codingChallenges[0])).to.equal(readFixes(codingChallenges[0]))
  })

  it('should not cache lookups for unknown keys', () => {
    const first = readFixes('unknownChallengeKey')
    expect(first.fixes).to.have.lengthOf(0)
    expect(readFixes('unknownChallengeKey')).to.not.equal(first)
  })

  it('should return no fixes for non-string keys', () => {
    const fixes = readFixes([codingChallenges[0]] as unknown as string)
    expect(fixes.fixes).to.have.lengthOf(0)
    expect(fixes.correct).to.equal(-1)
  })
})
