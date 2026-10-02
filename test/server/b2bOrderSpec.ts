/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import { b2bOrder } from '../../routes/b2bOrder'
const expect = chai.expect
chai.use(sinonChai)

describe('b2bOrder', () => {
  let req: any
  let res: any
  let next: any
  let save: any

  beforeEach(() => {
    req = { body: { } }
    res = { json: sinon.spy(), status: sinon.spy() }
    next = sinon.spy()
    save = () => ({
      then () { }
    })
    challenges.rceChallenge = { solved: false, save } as unknown as Challenge
  })

  it('infinite loop payload is rejected without being evaluated', () => {
    req.body.orderLinesData = '(function dos() { while(true); })()'

    b2bOrder()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
    expect(res.json).to.have.callCount(0)
    expect(challenges.rceChallenge.solved).to.equal(false)
  })

  it('sandbox breakout payload is rejected without being evaluated', () => {
    req.body.orderLinesData = 'this.constructor.constructor("return process")().exit()'

    b2bOrder()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
    expect(res.json).to.have.callCount(0)
  })

  it('non-string order lines data is rejected', () => {
    req.body.orderLinesData = { productId: 12 }

    b2bOrder()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
    expect(res.json).to.have.callCount(0)
  })

  it('deserializing JSON as documented in Swagger should not solve "rceChallenge"', () => {
    req.body.orderLinesData = '{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"}'

    b2bOrder()(req, res, next)

    expect(res.json).to.have.been.calledWith(sinon.match.has('orderNo'))
    expect(challenges.rceChallenge.solved).to.equal(false)
  })

  it('deserializing arbitrary JSON should not solve "rceChallenge"', () => {
    req.body.orderLinesData = '{"hello": "world", "foo": 42, "bar": [false, true]}'

    b2bOrder()(req, res, next)
    expect(challenges.rceChallenge.solved).to.equal(false)
  })

  it('deserializing broken JSON should not solve "rceChallenge"', () => {
    req.body.orderLinesData = '{ "productId: 28'

    b2bOrder()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
    expect(challenges.rceChallenge.solved).to.equal(false)
  })
})
