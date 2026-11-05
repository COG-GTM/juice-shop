/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import fs from 'node:fs'
import sinon from 'sinon'
import sinonChai from 'sinon-chai'
import { checkCorrectFix } from '../../routes/vulnCodeFixes'
const expect = chai.expect
chai.use(sinonChai)

describe('vulnCodeFixes', () => {
  const key = 'resetPasswordBenderChallenge'
  let res: any
  let next: any

  beforeEach(() => {
    res = { __: (s: string) => s, status: sinon.stub().returnsThis(), json: sinon.spy() }
    next = sinon.spy()
    delete (global as any).yamlFunctionExecuted
  })

  afterEach(() => {
    sinon.restore()
  })

  function stubInfoYml (content: string) {
    const readFileSync = fs.readFileSync
    sinon.stub(fs, 'readFileSync').callsFake(((path: any, options?: any) => {
      if (String(path).endsWith(`${key}.info.yml`)) return content
      return readFileSync(path, options)
    }) as any)
  }

  it('should not execute !!js/function tags from the coding challenge info YAML', async () => {
    stubInfoYml("fixes:\n  find: !!js/function 'function () { global.yamlFunctionExecuted = true; return undefined }'\n")
    const req: any = { body: { key, selectedFix: 42 } }

    let error: any
    try {
      await checkCorrectFix()(req, res, next)
    } catch (err) {
      error = err
    }

    expect((global as any).yamlFunctionExecuted).to.equal(undefined)
    expect(error?.name).to.equal('YAMLException')
  })

  it('should ignore fixes that are not a list in the coding challenge info YAML', async () => {
    stubInfoYml('fixes:\n  find: 1\n')
    const req: any = { body: { key, selectedFix: 42 } }

    await checkCorrectFix()(req, res, next)

    expect(res.status).to.have.been.calledWith(200)
    expect(res.json).to.have.been.calledWith({ verdict: false, explanation: undefined })
  })
})
