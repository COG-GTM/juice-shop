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

  it('accepts JSON order lines as documented in Swagger', () => {
    req.body.orderLinesData = '[{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"}]'

    b2bOrder()(req, res)

    expect(res.status).to.have.callCount(0)
    expect(res.json).to.have.been.calledWithMatch({ orderNo: sinon.match.string, paymentDue: sinon.match.string })
  })

  it('accepts arbitrary JSON order lines', () => {
    req.body.orderLinesData = '{"hello": "world", "foo": 42, "bar": [false, true]}'

    b2bOrder()(req, res)

    expect(res.status).to.have.callCount(0)
  })

  it('accepts orders without order lines data', () => {
    b2bOrder()(req, res)

    expect(res.status).to.have.callCount(0)
  })

  it('rejects broken JSON', () => {
    req.body.orderLinesData = '{ "productId: 28'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects JavaScript payloads instead of evaluating them', () => {
    for (const payload of [
      '(function dos() { while(true); })()',
      '/((a+)+)b/.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")',
      'this.constructor.constructor("return process")().exit()',
      'const a = []; while (true) a.push("x".repeat(1e7))'
    ]) {
      res.status.resetHistory()
      req.body.orderLinesData = payload

      b2bOrder()(req, res)

      expect(res.status).to.have.been.calledWith(400)
    }
  })
})
