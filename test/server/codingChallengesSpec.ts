/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { findFilesWithCodeChallenges, getCodeChallengesFromFile, SNIPPET_PATHS } from '../../lib/codingChallenges'
const expect = chai.expect

const start = '// vuln-code' + '-snippet start'
const end = '// vuln-code' + '-snippet end'

describe('codingChallenges', () => {
  let tmpDir: string

  before(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'snippets-'))
  })

  after(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true })
  })

  it('should not scan the data folder holding the SQLite database', () => {
    expect(SNIPPET_PATHS).to.not.include('./data')
  })

  it('should only read files with source code extensions', async () => {
    await fs.writeFile(path.join(tmpDir, 'test.sqlite'), `${start} leak\nsecret rows\n`)
    await fs.writeFile(path.join(tmpDir, 'source.ts'), `${start} sourceChallenge\nconst a = 1\n${end} sourceChallenge\n`)

    const matches = await findFilesWithCodeChallenges([tmpDir])

    expect(matches.map(match => path.basename(match.path))).to.deep.equal(['source.ts'])
  })

  it('should skip a challenge with broken boundaries instead of throwing', () => {
    const content = `${start} brokenChallenge\nconst a = 1\n${start} okChallenge\nconst b = 2\n${end} okChallenge\n`

    const challenges = getCodeChallengesFromFile({ path: 'test.ts', content })

    expect(challenges.map(challenge => challenge.challengeKey)).to.deep.equal(['okChallenge'])
    expect(challenges[0].snippet).to.equal('const b = 2')
  })

  it('should match challenge keys literally instead of as regular expressions', () => {
    const content = `${start} a.b\nconst a = 1\n${end} axb\n`

    expect(getCodeChallengesFromFile({ path: 'test.ts', content })).to.deep.equal([])
  })
})
