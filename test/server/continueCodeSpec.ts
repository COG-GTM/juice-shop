/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { continueCode } from '../../routes/continueCode'
import { decodeContinueCode, encodeContinueCode } from '../../lib/continueCode'

const expect = chai.expect
chai.use(sinonChai)

describe('continueCode', () => {
  let req: any
  let res: any

  beforeEach(() => {
    req = {}
    res = { json: sinon.spy() }
  })

  it('should be empty when no challenges are solved', () => {
    challenges.scoreBoardChallenge = { solved: false } as unknown as Challenge
    challenges.adminSectionChallenge = { solved: false } as unknown as Challenge

    continueCode()(req, res)
    expect(res.json).to.have.been.calledWith({ continueCode: undefined })
  })

  it('should be hashid value of IDs of solved challenges', () => {
    challenges.scoreBoardChallenge = { id: 1, solved: true } as unknown as Challenge
    challenges.adminSectionChallenge = { id: 2, solved: true } as unknown as Challenge
    challenges.continueCodeChallenge = { id: 3, solved: false } as unknown as Challenge

    continueCode()(req, res)
    const code: string = res.json.firstCall.args[0].continueCode
    expect(code.startsWith('yXjv6Z5jWJnzD6a3YvmwPRXK7roAyzHDde2Og19yEN84plqxkMBbLVQrDeoY')).to.equal(true)
    expect(decodeContinueCode('continueCode', code)).to.deep.equal([1, 2])
  })

  it('should not decode unsigned hashid values', () => {
    expect(decodeContinueCode('continueCode', 'yXjv6Z5jWJnzD6a3YvmwPRXK7roAyzHDde2Og19yEN84plqxkMBbLVQrDeoY')).to.deep.equal([])
  })

  it('should not decode continue codes with a tampered signature', () => {
    const code = encodeContinueCode('continueCode', [1, 2])
    const tampered = code.slice(0, -1) + (code.endsWith('0') ? '1' : '0')
    expect(decodeContinueCode('continueCode', tampered)).to.deep.equal([])
  })

  it('should not decode continue codes signed for another kind', () => {
    expect(decodeContinueCode('fixIt', encodeContinueCode('findIt', [1, 2]))).to.deep.equal([])
  })
})
