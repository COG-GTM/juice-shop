/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { restrictHintUpdate } from '../../routes/hintUpdate'

const expect = chai.expect
chai.use(sinonChai)

describe('hintUpdate', () => {
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    req = { body: {} }
    res = { status: sinon.stub().returnsThis(), json: sinon.spy() }
    next = sinon.spy()
  })

  it('passes { unlocked: true } through to finale', () => {
    req.body = { unlocked: true }

    restrictHintUpdate()(req, res, next)

    expect(next).to.have.been.calledWith()
    expect(req.body).to.deep.equal({ unlocked: true })
    expect(res.status).to.not.have.been.called
  })

  const rejected: Record<string, unknown> = {
    'hint text change': { text: 'Tampered hint' },
    'text change alongside unlock': { unlocked: true, text: 'Tampered hint' },
    'challenge reassignment alongside unlock': { unlocked: true, ChallengeId: 1 },
    're-locking a hint': { unlocked: false },
    'truthy non-boolean unlock': { unlocked: 'true' },
    'empty body': {},
    'array body': [{ unlocked: true }],
    'missing body': undefined
  }

  for (const [name, body] of Object.entries(rejected)) {
    it(`rejects ${name} with 403`, () => {
      req.body = body

      restrictHintUpdate()(req, res, next)

      expect(next).to.not.have.been.called
      expect(res.status).to.have.been.calledWith(403)
      expect(res.json).to.have.been.calledWith({ status: 'error', message: 'Only unlocking a hint is allowed.' })
    })
  }
})
