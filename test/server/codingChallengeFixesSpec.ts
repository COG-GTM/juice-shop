/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { retrieveChallengesWithCodeSnippet } from '../../routes/vulnCodeSnippet'
import { readFixes } from '../../routes/vulnCodeFixes'
import { getCodingChallengeInfo } from '../../lib/codingChallenges'
import chai from 'chai'
import fs from 'graceful-fs'
import nodeFs from 'node:fs'
import sinon from 'sinon'
import sinonChai from 'sinon-chai'
import yaml from 'js-yaml'
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

  describe('getCodingChallengeInfo', () => {
    afterEach(() => {
      sinon.restore()
    })

    it('should return the parsed info YAML file of a coding challenge', () => {
      for (const challenge of codingChallenges) {
        expect(getCodingChallengeInfo(challenge), `Coding challenge ${challenge} info YAML file was not parsed correctly`)
          .to.deep.equal(yaml.load(fs.readFileSync('./data/static/codefixes/' + challenge + '.info.yml', 'utf8')))
      }
    })

    it('should read each info YAML file only once', () => {
      for (const challenge of codingChallenges) getCodingChallengeInfo(challenge)
      const readFileSync = sinon.spy(nodeFs, 'readFileSync')
      const existsSync = sinon.spy(nodeFs, 'existsSync')
      for (const challenge of codingChallenges) {
        expect(getCodingChallengeInfo(challenge)).to.equal(getCodingChallengeInfo(challenge))
      }
      expect(readFileSync.callCount).to.equal(0)
      expect(existsSync.callCount).to.equal(0)
    })

    it('should return null for a challenge without info YAML file', () => {
      expect(getCodingChallengeInfo('noSuchChallenge')).to.equal(null)
      const existsSync = sinon.spy(nodeFs, 'existsSync')
      expect(getCodingChallengeInfo('noSuchChallenge')).to.equal(null)
      expect(existsSync.callCount).to.equal(0)
    })
  })
})
