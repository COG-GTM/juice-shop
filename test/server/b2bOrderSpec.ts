/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { b2bOrder } from '../../routes/b2bOrder'
const expect = chai.expect
chai.use(sinonChai)

describe('b2bOrder', () => {
  let req: any
  let res: any

  beforeEach(() => {
    req = { body: { } }
    res = { json: sinon.spy(), status: sinon.stub() }
    res.status.returns(res)
  })

  function expectRejected () {
    expect(res.status).to.have.been.calledWith(400)
    expect(res.json).to.have.been.calledWith({ status: 'error', error: 'Invalid orderLinesData' })
  }

  function expectAccepted () {
    expect(res.status).to.have.callCount(0)
    expect(res.json).to.have.been.calledWithMatch({ orderNo: sinon.match.string, paymentDue: sinon.match.string })
  }

  it('rejects an infinite loop payload without executing it', () => {
    req.body.orderLinesData = '(function dos() { while(true); })()'

    b2bOrder()(req, res)

    expectRejected()
  })

  it('rejects a catastrophic backtracking regex payload without executing it', () => {
    req.body.orderLinesData = '/((a+)+)b/.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")'

    b2bOrder()(req, res)

    expectRejected()
  })

  it('rejects a sandbox breakout payload without executing it', () => {
    req.body.orderLinesData = 'this.constructor.constructor("return process")().exit()'

    b2bOrder()(req, res)

    expectRejected()
  })

  it('accepts order lines as documented in Swagger', () => {
    req.body.orderLinesData = '[{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"},{"productId": 13,"quantity": 2000,"customerReference": "PO0000003.4"}]'

    b2bOrder()(req, res)

    expectAccepted()
  })

  it('accepts a single order line object', () => {
    req.body.orderLinesData = '{"productId": 12,"quantity": 10000}'

    b2bOrder()(req, res)

    expectAccepted()
  })

  it('accepts a request without orderLinesData', () => {
    req.body.cid = 'JS0815DE'

    b2bOrder()(req, res)

    expectAccepted()
    expect(res.json).to.have.been.calledWithMatch({ cid: 'JS0815DE' })
  })

  it('rejects arbitrary JSON that does not match the order line schema', () => {
    req.body.orderLinesData = '{"hello": "world", "foo": 42, "bar": [false, true]}'

    b2bOrder()(req, res)

    expectRejected()
  })

  it('rejects broken JSON', () => {
    req.body.orderLinesData = '{ "productId: 28'

    b2bOrder()(req, res)

    expectRejected()
  })

  it('rejects non-integer or non-positive quantities', () => {
    req.body.orderLinesData = '[{"productId": 1,"quantity": 0},{"productId": 2,"quantity": 1.5}]'

    b2bOrder()(req, res)

    expectRejected()
  })

  it('rejects an empty order line array', () => {
    req.body.orderLinesData = '[]'

    b2bOrder()(req, res)

    expectRejected()
  })

  it('rejects orderLinesData that is not a string', () => {
    req.body.orderLinesData = { productId: 1, quantity: 1 }

    b2bOrder()(req, res)

    expectRejected()
  })
})
