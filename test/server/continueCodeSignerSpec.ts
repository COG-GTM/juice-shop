/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

const expect = chai.expect

type Signer = typeof import('../../lib/continueCodeSigner')

const keyFile = path.resolve('data/continue-code.key')
const signerPath = require.resolve('../../lib/continueCodeSigner')
const startSigner = (): Signer => {
  delete require.cache[signerPath]
  return require(signerPath)
}

describe('continueCodeSigner', () => {
  let previousKey: string | undefined
  let previousEnv: string | undefined

  beforeEach(() => {
    previousEnv = process.env.CONTINUE_CODE_SECRET
    delete process.env.CONTINUE_CODE_SECRET
    previousKey = fs.existsSync(keyFile) ? fs.readFileSync(keyFile, 'utf8') : undefined
  })

  afterEach(() => {
    if (previousEnv === undefined) delete process.env.CONTINUE_CODE_SECRET
    else process.env.CONTINUE_CODE_SECRET = previousEnv
    if (previousKey === undefined) fs.rmSync(keyFile, { force: true })
    else fs.writeFileSync(keyFile, previousKey, { mode: 0o600 })
    delete require.cache[signerPath]
  })

  it('should keep codes valid across a restart by reusing the persisted key', () => {
    const code = startSigner().sign('abc', 'hacking')
    expect(startSigner().verify(code, 'hacking')).to.equal('abc')
  })

  it('should generate and persist a key on first start and reject codes signed with a previous key', () => {
    const oldCode = startSigner().sign('abc', 'hacking')
    fs.rmSync(keyFile)
    const signer = startSigner()
    const generated = fs.readFileSync(keyFile, 'utf8')
    expect(generated).to.match(/^[0-9a-f]{64}$/)
    expect(generated).to.not.equal(previousKey)
    expect(signer.verify(oldCode, 'hacking')).to.equal(null)
    expect(startSigner().verify(signer.sign('abc', 'hacking'), 'hacking')).to.equal('abc')
  })

  it('should sign with CONTINUE_CODE_SECRET instead of the persisted key', () => {
    process.env.CONTINUE_CODE_SECRET = 'x'.repeat(40)
    const code = startSigner().sign('abc', 'fixIt')
    expect(code).to.equal('abc' + crypto.createHmac('sha256', 'x'.repeat(40)).update('fixIt:abc').digest('hex'))
    fs.writeFileSync(keyFile, crypto.randomBytes(32).toString('hex'))
    expect(startSigner().verify(code, 'fixIt')).to.equal('abc')
  })

  it('should ignore a CONTINUE_CODE_SECRET shorter than 32 characters', () => {
    const code = startSigner().sign('abc', 'findIt')
    process.env.CONTINUE_CODE_SECRET = 'too short'
    expect(startSigner().verify(code, 'findIt')).to.equal('abc')
  })
})
