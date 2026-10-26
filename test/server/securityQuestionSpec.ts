/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { SecurityAnswerModel } from '../../models/securityAnswer'
import { SecurityQuestionModel } from '../../models/securityQuestion'
import { securityQuestion } from '../../routes/securityQuestion'

const expect = chai.expect
chai.use(sinonChai)

describe('securityQuestion', () => {
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    res = { json: sinon.spy() }
    next = sinon.spy()
  })

  afterEach(() => {
    sinon.restore()
  })

  it('should return the security question of the user with the given email', async () => {
    const question = { id: 2, question: 'Your eldest siblings middle name?' }
    const findAnswer = sinon.stub(SecurityAnswerModel, 'findOne').resolves({ SecurityQuestionId: 2 } as any)
    const findQuestion = sinon.stub(SecurityQuestionModel, 'findByPk').resolves(question as any)
    req = { query: { email: 'jim@juice-sh.op' } }

    await securityQuestion()(req, res, next)

    expect(findAnswer).to.have.been.calledWith(sinon.match({ include: [sinon.match({ where: { email: 'jim@juice-sh.op' } })] }))
    expect(findQuestion).to.have.been.calledWith(2)
    expect(res.json).to.have.been.calledWith({ question })
  })

  it('should return empty object for unknown email', async () => {
    sinon.stub(SecurityAnswerModel, 'findOne').resolves(null)
    const findQuestion = sinon.stub(SecurityQuestionModel, 'findByPk')
    req = { query: { email: 'unknown@juice-sh.op' } }

    await securityQuestion()(req, res, next)

    expect(findQuestion).to.have.not.been.calledWith(sinon.match.any)
    expect(res.json).to.have.been.calledWith({})
  })

  it('should pass database errors to next', async () => {
    const error = new Error('DB down')
    sinon.stub(SecurityAnswerModel, 'findOne').rejects(error)
    req = { query: { email: 'jim@juice-sh.op' } }

    await securityQuestion()(req, res, next)

    expect(next).to.have.been.calledWith(error)
  })
})
