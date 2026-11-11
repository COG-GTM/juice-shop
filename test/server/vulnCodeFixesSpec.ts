/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import chai from 'chai'
import sinon from 'sinon'
import sinonChai from 'sinon-chai'
import { checkCorrectFix } from '../../routes/vulnCodeFixes'
const expect = chai.expect
chai.use(sinonChai)

describe('vulnCodeFixes', () => {
  const key = 'unsafeYamlTestChallenge'
  const dir = 'data/static/codefixes'
  const files = [`${dir}/${key}_1.ts`, `${dir}/${key}_2_correct.ts`, `${dir}/${key}.info.yml`]

  before(() => {
    fs.writeFileSync(files[0], 'fix 1')
    fs.writeFileSync(files[1], 'fix 2')
    fs.writeFileSync(files[2], 'fixes: { find: !!js/function \'function(){ global.unsafeYamlExecuted = true; return undefined }\' }\nhints: { length: !!js/function \'function(){ global.unsafeYamlExecuted = true; return 0 }\' }\n')
  })

  after(() => {
    files.forEach(file => { fs.rmSync(file, { force: true }) })
    delete (global as any).unsafeYamlExecuted
  })

  it('should refuse to deserialize JavaScript functions from coding challenge info files', async () => {
    const req: any = { body: { key, selectedFix: 0 } }
    const res: any = { __: sinon.stub(), status: sinon.stub().returnsThis(), json: sinon.stub() }
    const next: any = sinon.stub()

    let error: any
    try {
      await checkCorrectFix()(req, res, next)
    } catch (err) {
      error = err
    }

    expect(error?.name).to.equal('YAMLException')
    expect(error?.message).to.contain('!<tag:yaml.org,2002:js/function>')
    expect((global as any).unsafeYamlExecuted).to.equal(undefined)
  })
})
