/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { checkVulnLines, retrieveChallengesWithCodeSnippet } from '../../routes/vulnCodeSnippet'
import { checkCorrectFix, readFixes } from '../../routes/vulnCodeFixes'
import { getCodingChallengeInfo, loadCodingChallengeInfos, parseCodingChallengeInfo } from '../../lib/codingChallenges'
import chai from 'chai'
import fs from 'graceful-fs'
import os from 'node:os'
import path from 'node:path'
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
})

describe('codingChallengeInfo', () => {
  it('should load a valid info file for each shipped coding challenge', async () => {
    const infos = loadCodingChallengeInfos()
    for (const challenge of await retrieveChallengesWithCodeSnippet()) {
      const info = infos.get(challenge)
      expect(info, `Coding challenge ${challenge} has no valid info YAML file`).to.not.equal(undefined)
      expect(info?.fixes.length).to.be.greaterThan(0)
      expect(getCodingChallengeInfo(challenge)).to.deep.equal(info)
    }
  })

  it('should not execute !!js/function tags in info files', () => {
    let executed = false
    ;(globalThis as any).__codingChallengeInfoExecuted = () => { executed = true }
    try {
      for (const source of [
        'fixes: { find: !!js/function "function () { globalThis.__codingChallengeInfoExecuted() }" }',
        'hints: !!js/function "function () { globalThis.__codingChallengeInfoExecuted() }"',
        'fixes:\n  - id: !!js/undefined ""\n    explanation: x'
      ]) {
        expect(() => parseCodingChallengeInfo(source)).to.throw(/unknown tag/)
      }
    } finally {
      delete (globalThis as any).__codingChallengeInfoExecuted
    }
    expect(executed).to.equal(false)
  })

  it('should reject info files that do not match the expected shape', () => {
    for (const source of [
      'fixes: { find: 1 }',
      'fixes:\n  - id: "1"\n    explanation: x',
      'fixes:\n  - id: 1\n    explanation: 2',
      'fixes:\n  - id: 1\n    explanation: x\n    extra: y',
      'hints: [1]',
      'hints: x',
      'other: x',
      '- x'
    ]) {
      expect(() => parseCodingChallengeInfo(source), source).to.throw()
    }
  })

  it('should ignore invalid info files and keep loaded infos when files change later', () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'codefixes-'))
    try {
      fs.writeFileSync(path.join(directory, 'goodChallenge.info.yml'), 'fixes:\n  - id: 1\n    explanation: Good\nhints:\n  - Hint\n')
      fs.writeFileSync(path.join(directory, 'evilChallenge.info.yml'), 'fixes: { find: !!js/function "function () { throw new Error(\'executed\') }" }\n')
      const infos = loadCodingChallengeInfos(directory)
      expect([...infos.keys()]).to.deep.equal(['goodChallenge'])

      fs.writeFileSync(path.join(directory, 'goodChallenge.info.yml'), 'fixes:\n  - id: 1\n    explanation: Overwritten\n')
      expect(infos.get('goodChallenge')).to.deep.equal({ fixes: [{ id: 1, explanation: 'Good' }], hints: ['Hint'] })
      expect(Object.isFrozen(infos.get('goodChallenge')?.fixes)).to.equal(true)
    } finally {
      fs.rmSync(directory, { recursive: true, force: true })
    }
  })
})

describe('checkCorrectFix', () => {
  const codefixesDir = './data/static/codefixes'
  const maliciousInfo = 'fixes: { find: !!js/function "function () { globalThis.__checkCorrectFixExecuted = true; return { explanation: \'pwned\' } }" }\n'

  const callCheckCorrectFix = async (key: string, selectedFix: number) => {
    const result: { status?: number, body?: any } = {}
    const res: any = {
      __: (text: string) => text,
      status (code: number) { result.status = code; return this },
      json (body: unknown) { result.body = body; return this }
    }
    await checkCorrectFix()({ body: { key, selectedFix } } as any, res, () => {})
    return result
  }

  afterEach(() => {
    delete (globalThis as any).__checkCorrectFixExecuted
  })

  it('should not execute a !!js/function planted into an existing info file', async () => {
    const infoFile = path.join(codefixesDir, 'resetPasswordBenderChallenge.info.yml')
    const original = fs.readFileSync(infoFile, 'utf8')
    try {
      fs.writeFileSync(infoFile, maliciousInfo)
      const result = await callCheckCorrectFix('resetPasswordBenderChallenge', 0)
      expect((globalThis as any).__checkCorrectFixExecuted).to.equal(undefined)
      expect(result.status).to.equal(200)
      expect(result.body.verdict).to.equal(false)
      expect(result.body.explanation).to.not.equal('pwned')
    } finally {
      fs.writeFileSync(infoFile, original)
    }
  })

  it('should reject unknown keys even when matching fix and info files are planted', async () => {
    const planted = [path.join(codefixesDir, 'plantedRceChallenge.info.yml'), path.join(codefixesDir, 'plantedRceChallenge_1_correct.ts')]
    try {
      fs.writeFileSync(planted[0], maliciousInfo)
      fs.writeFileSync(planted[1], '')
      const result = await callCheckCorrectFix('plantedRceChallenge', 0)
      expect((globalThis as any).__checkCorrectFixExecuted).to.equal(undefined)
      expect(result.status).to.equal(404)
      expect(result.body).to.deep.equal({ error: 'No fixes found for the snippet!' })
    } finally {
      for (const file of planted) fs.rmSync(file, { force: true })
    }
  })

  it('should reject non-string keys', async () => {
    const result = await callCheckCorrectFix({ toString: () => 'resetPasswordBenderChallenge' } as any, 0)
    expect(result.status).to.equal(404)
  })
})

describe('checkVulnLines', () => {
  const infoFile = './data/static/codefixes/loginAdminChallenge.info.yml'
  const maliciousInfo = 'hints:\n  length:\n    valueOf: !!js/function "function () { globalThis.__checkVulnLinesExecuted = true; return 0 }"\n'

  const callCheckVulnLines = async (key: string, selectedLines: number[]) => {
    const result: { status?: number, body?: any } = {}
    const res: any = {
      __: (text: string) => text,
      status (code: number) { result.status = code; return this },
      json (body: unknown) { result.body = body; return this }
    }
    await checkVulnLines()({ body: { key, selectedLines } } as any, res, () => {})
    return result
  }

  afterEach(() => {
    delete (globalThis as any).__checkVulnLinesExecuted
  })

  it('should not execute a !!js/function valueOf planted as hints.length in an existing info file', async () => {
    const original = fs.readFileSync(infoFile, 'utf8')
    try {
      fs.writeFileSync(infoFile, maliciousInfo)
      const result = await callCheckVulnLines('loginAdminChallenge', [])
      expect((globalThis as any).__checkVulnLinesExecuted).to.equal(undefined)
      expect(result.status).to.equal(200)
      expect(result.body.verdict).to.equal(false)
      expect(getCodingChallengeInfo('loginAdminChallenge')?.hints).to.deep.equal(parseCodingChallengeInfo(original).hints)
    } finally {
      fs.writeFileSync(infoFile, original)
    }
  })
})
