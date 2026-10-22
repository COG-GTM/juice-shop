/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { findFilesWithCodeChallenges } from '../../lib/codingChallenges'
const expect = chai.expect

describe('codingChallenges', () => {
  let dir: string

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'codingChallenges-'))
    fs.writeFileSync(path.join(dir, 'a.ts'), '// vuln-code' + '-snippet start aChallenge\n')
    fs.writeFileSync(path.join(dir, 'plain.ts'), 'const x = 1\n')
    fs.mkdirSync(path.join(dir, 'sub'))
    fs.writeFileSync(path.join(dir, 'sub', 'b.py'), '# vuln-code' + '-snippet start bChallenge\n')
  })

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true })
  })

  it('should find files with code challenges in nested directories', async () => {
    const matches = await findFilesWithCodeChallenges([dir])
    expect(matches.map(match => path.relative(dir, match.path)).sort()).to.deep.equal(['a.ts', path.join('sub', 'b.py')])
    expect(matches.find(match => match.path.endsWith('a.ts'))?.content).to.equal('// vuln-code' + '-snippet start aChallenge\n')
  })

  it('should skip paths that do not exist', async () => {
    const matches = await findFilesWithCodeChallenges([path.join(dir, 'missing.ts'), path.join(dir, 'a.ts')])
    expect(matches.map(match => path.relative(dir, match.path))).to.deep.equal(['a.ts'])
  })
})
