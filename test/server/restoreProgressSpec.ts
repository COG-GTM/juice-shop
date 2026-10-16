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
import { restoreProgress } from '../../routes/restoreProgress'

const expect = chai.expect
chai.use(sinonChai)

describe('restoreProgress', () => {
  const continueCodeFor = (...ids: number[]) => new Hashids('this is my salt', 60, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890').encode(ids)
  let res: any

  beforeEach(() => {
    res = { json: sinon.spy(), end: sinon.spy(), status: sinon.stub().returnsThis(), send: sinon.spy() }
    challenges.continueCodeChallenge = { id: 3, solved: true } as unknown as Challenge
  })

  it('should restore unsolved challenges listed in the continue code', () => {
    const save = sinon.stub().returns(new Promise(() => {}))
    challenges.scoreBoardChallenge = { id: 9001, solved: false, save } as unknown as Challenge

    restoreProgress()({ params: { continueCode: continueCodeFor(9001) } } as any, res)

    expect(save).to.have.been.calledOnce
    expect(challenges.scoreBoardChallenge.solved).to.equal(true)
    expect(res.json).to.have.been.calledWith({ data: '1 solved challenges have been restored.' })
  })

  it('should not re-solve challenges that are already solved', () => {
    const save = sinon.stub().returns(new Promise(() => {}))
    challenges.scoreBoardChallenge = { id: 9001, solved: true, save } as unknown as Challenge

    restoreProgress()({ params: { continueCode: continueCodeFor(9001) } } as any, res)
    restoreProgress()({ params: { continueCode: continueCodeFor(9001) } } as any, res)

    expect(save).to.have.callCount(0)
  })

  it('should ignore challenges not listed in the continue code', () => {
    const save = sinon.stub().returns(new Promise(() => {}))
    challenges.scoreBoardChallenge = { id: 9001, solved: false, save } as unknown as Challenge

    restoreProgress()({ params: { continueCode: continueCodeFor(9002) } } as any, res)

    expect(save).to.have.callCount(0)
    expect(challenges.scoreBoardChallenge.solved).to.equal(false)
  })
})
