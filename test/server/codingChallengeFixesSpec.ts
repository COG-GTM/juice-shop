/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { retrieveChallengesWithCodeSnippet, checkVulnLines } from '../../routes/vulnCodeSnippet'
import { readFixes, isKnownFixKey, checkCorrectFix } from '../../routes/vulnCodeFixes'
import chai from 'chai'
import fs from 'graceful-fs'
import yaml from 'js-yaml'
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

  it('should parse all coding challenge info YAML files with the safe schema', () => {
    for (const file of fs.readdirSync('./data/static/codefixes').filter((f: string) => f.endsWith('.info.yml'))) {
      expect(() => yaml.safeLoad(fs.readFileSync('./data/static/codefixes/' + file, 'utf8')), `${file} is not safe-loadable`).to.not.throw()
    }
  })

  describe('with an info YAML file containing an unsafe tag', () => {
    const unsafeYaml = 'fixes: !!js/function "function () { return 42 }"\nhints: !!js/function "function () { return 42 }"\n'
    let readFile: sinon.SinonStub
    beforeEach(() => {
      readFixes('resetPasswordBenderChallenge')
      const original = nodeFs.readFileSync
      readFile = sinon.stub(nodeFs, 'readFileSync').callsFake(((path: string, ...args: unknown[]) =>
        typeof path === 'string' && path.endsWith('.info.yml') ? unsafeYaml : (original as (...a: unknown[]) => unknown)(path, ...args)) as typeof nodeFs.readFileSync)
    })
    afterEach(() => {
      readFile.restore()
    })

    const res = () => ({ __: (s: string) => s, status: sinon.stub().returnsThis(), json: sinon.spy() })

    it('should refuse to deserialize it when checking a fix', async () => {
      const req: any = { body: { key: 'resetPasswordBenderChallenge', selectedFix: 0 } }
      let error: unknown
      try { await checkCorrectFix()(req, res() as any, () => {}) } catch (e) { error = e }
      expect(String(error)).to.match(/unknown tag/)
    })

    it('should refuse to deserialize it when checking vulnerable lines', async () => {
      const req: any = { body: { key: 'resetPasswordBenderChallenge', selectedLines: [] } }
      let error: unknown
      try { await checkVulnLines()(req, res() as any, () => {}) } catch (e) { error = e }
      expect(String(error)).to.match(/unknown tag/)
    })
  })

  it('should only accept keys of existing coding challenge fixes', () => {
    expect(isKnownFixKey('resetPasswordBenderChallenge')).to.equal(true)
    for (const key of ['doesNotExistChallenge', '__proto__', 'constructor', 'toString', '../../../etc/passwd', '../codefixes/resetPasswordBenderChallenge', 'resetPasswordBenderChallenge.info.yml', '', ['resetPasswordBenderChallenge'], { key: 'resetPasswordBenderChallenge' }, 42]) {
      expect(isKnownFixKey(key), `Key ${JSON.stringify(key)} was accepted`).to.equal(false)
      const fixes = readFixes(key as string)
      expect(fixes.fixes, `Key ${JSON.stringify(key)} returned fixes`).to.have.lengthOf(0)
      expect(fixes.correct).to.equal(-1)
    }
  })

  it('should not touch the filesystem or grow a cache for unknown keys once the fixes are loaded', () => {
    readFixes('resetPasswordBenderChallenge')
    const readdir = sinon.spy(nodeFs, 'readdirSync')
    const readFile = sinon.spy(nodeFs, 'readFileSync')
    try {
      for (let i = 0; i < 1000; i++) {
        expect(readFixes(`unknownChallenge${i}`).fixes).to.have.lengthOf(0)
        expect(readFixes(`../../x${i}`).fixes).to.have.lengthOf(0)
      }
      expect(readFixes('resetPasswordBenderChallenge').fixes).to.have.lengthOf(3)
      expect(readdir).to.have.callCount(0)
      expect(readFile).to.have.callCount(0)
    } finally {
      readdir.restore()
      readFile.restore()
    }
  })
})
