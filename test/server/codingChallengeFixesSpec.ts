/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { retrieveChallengesWithCodeSnippet } from '../../routes/vulnCodeSnippet'
import { readFixes } from '../../routes/vulnCodeFixes'
import { getCodingChallengeInfo } from '../../lib/codingChallenges'
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

  describe('getCodingChallengeInfo', () => {
    const writeInfoFile = (key: string, content: string) => {
      const file = `./data/static/codefixes/${key}.info.yml`
      fs.writeFileSync(file, content)
      return file
    }

    it('should not instantiate JavaScript functions from an info YAML file', () => {
      const file = writeInfoFile('yamlFunctionTagTestChallenge', 'fixes: { find: !!js/function "function () { throw new Error(\'executed\') }" }\n')
      try {
        expect(getCodingChallengeInfo('yamlFunctionTagTestChallenge')).to.equal(null)
      } finally {
        fs.unlinkSync(file)
      }
    })

    it('should drop malformed fixes and hints from an info YAML file', () => {
      const file = writeInfoFile('yamlShapeTestChallenge', 'fixes:\n  - id: 1\n    explanation: ok\n  - id: two\n    explanation: bad\nhints:\n  - hint\n  - { foo: bar }\n')
      try {
        expect(getCodingChallengeInfo('yamlShapeTestChallenge')).to.deep.equal({ fixes: [{ id: 1, explanation: 'ok' }], hints: ['hint'] })
      } finally {
        fs.unlinkSync(file)
      }
    })

    it('should reject challenge keys that are not alphanumeric', () => {
      expect(getCodingChallengeInfo('../codefixes/accessLogDisclosureChallenge')).to.equal(null)
    })

    it('should load fixes and hints for every coding challenge', async () => {
      for (const challenge of codingChallenges) {
        const info = getCodingChallengeInfo(challenge)
        expect(info?.fixes.length, `Coding challenge ${challenge} has no valid fix explanations`).to.be.greaterThan(0)
        expect(info?.hints.length, `Coding challenge ${challenge} has no valid hints`).to.be.greaterThan(0)
      }
    })
  })
})
