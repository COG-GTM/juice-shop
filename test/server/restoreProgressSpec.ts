/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import Hashids from 'hashids/cjs'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import * as security from '../../lib/insecurity'
import { continueCode } from '../../routes/continueCode'
import { restoreProgress, restoreProgressFindIt, restoreProgressFixIt } from '../../routes/restoreProgress'

const expect = chai.expect
chai.use(sinonChai)

const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
const forge = (salt: string, ids: number[]) => new Hashids(salt, 60, alphabet).encode(ids)

describe('restoreProgress', () => {
  let res: any
  let saved: Record<string, Challenge>
  const save = () => ({ then () {} })

  before(() => {
    saved = { ...challenges }
  })

  after(() => {
    for (const key of Object.keys(challenges)) Reflect.deleteProperty(challenges, key)
    Object.assign(challenges, saved)
  })

  beforeEach(() => {
    for (const key of Object.keys(challenges)) Reflect.deleteProperty(challenges, key)
    challenges.scoreBoardChallenge = { id: 1, solved: false, save } as unknown as Challenge
    challenges.adminSectionChallenge = { id: 2, solved: false, save } as unknown as Challenge
    challenges.continueCodeChallenge = { id: 3, solved: false, save } as unknown as Challenge
    res = { json: sinon.spy(), end: sinon.spy(), send: sinon.spy(), status: sinon.stub() }
    res.status.returns(res)
  })

  it('should reject an unsigned code forged with the public salt', () => {
    restoreProgress()({ params: { continueCode: forge('this is my salt', [1, 2]) } } as any, res)

    expect(res.status).to.have.been.calledWith(404)
    expect(challenges.scoreBoardChallenge.solved).to.equal(false)
    expect(challenges.adminSectionChallenge.solved).to.equal(false)
  })

  it('should reject a forged code with an invalid signature', () => {
    restoreProgress()({ params: { continueCode: forge('this is my salt', [1, 2]) + '.' + 'a'.repeat(64) } } as any, res)

    expect(res.status).to.have.been.calledWith(404)
    expect(challenges.scoreBoardChallenge.solved).to.equal(false)
  })

  it('should reject a code signed for a different continue code type', () => {
    const code = forge('this is my salt', [1, 2])
    const findItSigned = security.signContinueCode('continueCodeFindIt', code)
    restoreProgress()({ params: { continueCode: findItSigned } } as any, res)

    expect(res.status).to.have.been.calledWith(404)
    expect(challenges.scoreBoardChallenge.solved).to.equal(false)
  })

  it('should restore progress from a continue code issued by the server', () => {
    const issued = { json: sinon.spy() }
    challenges.scoreBoardChallenge.solved = true
    challenges.adminSectionChallenge.solved = true
    continueCode()({} as any, issued as any)
    const code = issued.json.firstCall.args[0].continueCode
    challenges.scoreBoardChallenge.solved = false
    challenges.adminSectionChallenge.solved = false

    restoreProgress()({ params: { continueCode: code } } as any, res)

    expect(res.json).to.have.been.calledWith({ data: '2 solved challenges have been restored.' })
    expect(challenges.scoreBoardChallenge.solved).to.equal(true)
    expect(challenges.adminSectionChallenge.solved).to.equal(true)
    expect(challenges.continueCodeChallenge.solved).to.equal(false)
  })

  it('should still solve only the "Imaginary Challenge" for a forged code containing #999', () => {
    restoreProgress()({ params: { continueCode: forge('this is my salt', [1, 2, 999]) } } as any, res)

    expect(res.end).to.have.been.calledWith()
    expect(challenges.continueCodeChallenge.solved).to.equal(true)
    expect(challenges.scoreBoardChallenge.solved).to.equal(false)
    expect(challenges.adminSectionChallenge.solved).to.equal(false)
  })

  it('should reject an unsigned "Find It" code forged with the public salt', async () => {
    await restoreProgressFindIt()({ params: { continueCode: forge('this is the salt for findIt challenges', [1, 2]) } } as any, res)

    expect(res.status).to.have.been.calledWith(404)
    expect(res.json).to.have.callCount(0)
  })

  it('should reject an unsigned "Fix It" code forged with the public salt', async () => {
    await restoreProgressFixIt()({ params: { continueCode: forge('yet another salt for the fixIt challenges', [1, 2]) } } as any, res)

    expect(res.status).to.have.been.calledWith(404)
    expect(res.json).to.have.callCount(0)
  })
})
