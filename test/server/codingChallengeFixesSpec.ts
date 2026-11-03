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

  it('should have an info YAML file for each coding challenge', async () => {
    for (const challenge of codingChallenges) {
      expect(fs.existsSync('./data/static/codefixes/' + challenge + '.info.yml'), `Coding challenge ${challenge} does not have an info YAML file`).to.equal(true)
    }
  })

  it('should return no fixes for unknown, inherited or non-string keys', () => {
    for (const key of ['doesNotExistChallenge', '__proto__', 'constructor', 'toString', '', 'resetPasswordBenderChallenge.info.yml', 'x'.repeat(100000), ['resetPasswordBenderChallenge'], { key: 'resetPasswordBenderChallenge' }, 42, undefined]) {
      const fixes = readFixes(key)
      expect(fixes.fixes, `Key ${String(key).substring(0, 40)} returned fixes`).to.have.lengthOf(0)
      expect(fixes.correct).to.equal(-1)
    }
  })

  it('should not read the filesystem or cache anything for unknown keys', () => {
    expect(readFixes('resetPasswordBenderChallenge').fixes).to.have.lengthOf(3)
    const readdir = sinon.spy(nodeFs, 'readdirSync')
    const readFile = sinon.spy(nodeFs, 'readFileSync')
    try {
      for (let i = 0; i < 1000; i++) {
        expect(readFixes(`unknownChallenge${i}`).fixes).to.have.lengthOf(0)
      }
      expect(readFixes('unknownChallenge0')).to.not.equal(readFixes('unknownChallenge0'))
      expect(readFixes('resetPasswordBenderChallenge').fixes).to.have.lengthOf(3)
      expect(readdir).to.have.callCount(0)
      expect(readFile).to.have.callCount(0)
    } finally {
      readdir.restore()
      readFile.restore()
    }
  })
})
