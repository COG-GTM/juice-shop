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
import { ChallengeModel } from '../../models/challenge'
import { restoreProgress, restoreProgressFindIt, restoreProgressFixIt } from '../../routes/restoreProgress'
import { sign } from '../../lib/continueCodeSigner'

const expect = chai.expect
chai.use(sinonChai)

const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
const forge = (salt: string, ids: number[]) => new Hashids(salt, 60, alphabet).encode(ids)

describe('restoreProgress', () => {
  let res: any
  let save: sinon.SinonStub
  let update: sinon.SinonStub

  beforeEach(() => {
    res = { json: sinon.spy(), end: sinon.spy(), status: sinon.stub().returnsThis(), send: sinon.spy() }
    save = sinon.stub().returns(new Promise(() => {}))
    update = sinon.stub(ChallengeModel, 'update').resolves([1])
    challenges.scoreBoardChallenge = { id: 1, key: 'scoreBoardChallenge', solved: false, save } as unknown as Challenge
    challenges.adminSectionChallenge = { id: 2, key: 'adminSectionChallenge', solved: false, save } as unknown as Challenge
    challenges.continueCodeChallenge = { id: 3, key: 'continueCodeChallenge', solved: false, save } as unknown as Challenge
  })

  afterEach(() => {
    sinon.restore()
  })

  it('should reject a code forged with the public Hashids salt', () => {
    restoreProgress()({ params: { continueCode: forge('this is my salt', [1, 2]) } } as any, res)
    expect(res.status).to.have.been.calledWith(404)
    expect(save).to.have.callCount(0)
  })

  it('should not solve the imaginary challenge #999 from a forged code', () => {
    restoreProgress()({ params: { continueCode: forge('this is my salt', [999]) } } as any, res)
    expect(res.status).to.have.been.calledWith(404)
    expect(save).to.have.callCount(0)
  })

  it('should reject a signed code whose payload has been tampered with', () => {
    const tampered = forge('this is my salt', [1, 2, 3]) + sign(forge('this is my salt', [1]), 'hacking').slice(-64)
    restoreProgress()({ params: { continueCode: tampered } } as any, res)
    expect(res.status).to.have.been.calledWith(404)
    expect(save).to.have.callCount(0)
  })

  it('should restore challenges from a server-signed code', () => {
    restoreProgress()({ params: { continueCode: sign(forge('this is my salt', [1, 2]), 'hacking') } } as any, res)
    expect(save).to.have.callCount(2)
    expect(res.json).to.have.been.calledWith({ data: '2 solved challenges have been restored.' })
  })

  it('should reject a code signed for a different scope', async () => {
    await restoreProgressFindIt()({ params: { continueCode: sign(forge('this is the salt for findIt challenges', [1]), 'hacking') } } as any, res)
    expect(res.status).to.have.been.calledWith(404)
    expect(update).to.have.callCount(0)
  })

  it('should reject forged findIt and fixIt codes', async () => {
    await restoreProgressFindIt()({ params: { continueCode: forge('this is the salt for findIt challenges', [1, 2]) } } as any, res)
    await restoreProgressFixIt()({ params: { continueCode: forge('yet another salt for the fixIt challenges', [1, 2]) } } as any, res)
    expect(res.status).to.have.callCount(2)
    expect(update).to.have.callCount(0)
  })

  it('should restore findIt and fixIt challenges from server-signed codes', async () => {
    await restoreProgressFindIt()({ params: { continueCode: sign(forge('this is the salt for findIt challenges', [1]), 'findIt') } } as any, res)
    await restoreProgressFixIt()({ params: { continueCode: sign(forge('yet another salt for the fixIt challenges', [2]), 'fixIt') } } as any, res)
    expect(update).to.have.been.calledWithMatch({ codingChallengeStatus: 1 }, { where: { key: 'scoreBoardChallenge' } })
    expect(update).to.have.been.calledWithMatch({ codingChallengeStatus: 2 }, { where: { key: 'adminSectionChallenge' } })
  })
})
