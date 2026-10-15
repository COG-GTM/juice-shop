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
  let save: any

  beforeEach(() => {
    req = { body: { } }
    res = { json: sinon.spy(), status: sinon.stub().returnsThis() }
    save = () => ({
      then () { }
    })
    challenges.rceChallenge = { solved: false, save } as unknown as Challenge
    challenges.rceOccupyChallenge = { solved: false, save } as unknown as Challenge
  })

  it('infinite loop payload is rejected without being evaluated', () => {
    req.body.orderLinesData = '(function dos() { while(true); })()'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
    expect(challenges.rceChallenge.solved).to.equal(false)
  })

  it('catastrophic backtracking regex payload is rejected without being evaluated', () => {
    req.body.orderLinesData = '/((a+)+)b/.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
    expect(challenges.rceOccupyChallenge.solved).to.equal(false)
  })

  it('sandbox breakout payload is rejected without being evaluated', () => {
    const exit = sinon.stub(process, 'exit')
    try {
      req.body.orderLinesData = 'this.constructor.constructor("return process")().exit()'

      b2bOrder()(req, res)

      expect(exit).to.have.callCount(0)
      expect(res.status).to.have.been.calledWith(400)
    } finally {
      exit.restore()
    }
  })

  it('order lines as documented in Swagger are accepted', () => {
    req.body.cid = 'JS0815DE'
    req.body.orderLinesData = '[{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"},{"productId": 13,"quantity": 2000,"customerReference": "PO0000003.4"}]'

    b2bOrder()(req, res)

    expect(res.status).to.have.callCount(0)
    expect(res.json).to.have.been.calledWith(sinon.match({ cid: 'JS0815DE', orderNo: sinon.match.string, paymentDue: sinon.match.string }))
    expect(challenges.rceChallenge.solved).to.equal(false)
  })

  it('single order line object is accepted', () => {
    req.body.orderLinesData = '{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"}'

    b2bOrder()(req, res)

    expect(res.status).to.have.callCount(0)
    expect(res.json).to.have.been.calledWith(sinon.match({ orderNo: sinon.match.string }))
  })

  it('missing orderLinesData is accepted', () => {
    b2bOrder()(req, res)

    expect(res.status).to.have.callCount(0)
    expect(res.json).to.have.been.calledWith(sinon.match({ orderNo: sinon.match.string }))
  })

  it('JSON not matching the order line schema is rejected', () => {
    req.body.orderLinesData = '{"hello": "world", "foo": 42, "bar": [false, true]}'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
    expect(challenges.rceChallenge.solved).to.equal(false)
  })

  it('order line with non-positive quantity is rejected', () => {
    req.body.orderLinesData = '[{"productId": 12,"quantity": 0}]'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('non-string orderLinesData is rejected', () => {
    req.body.orderLinesData = [{ productId: 12, quantity: 1 }]

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('broken JSON is rejected', () => {
    req.body.orderLinesData = '{ "productId: 28'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
    expect(challenges.rceChallenge.solved).to.equal(false)
  })
})
