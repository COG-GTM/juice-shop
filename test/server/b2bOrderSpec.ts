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
  let next: any

  beforeEach(() => {
    req = { body: { } }
    res = { json: sinon.spy() }
    res.status = sinon.stub().returns(res)
    next = sinon.spy()
  })

  it('infinite loop payload is rejected without being executed', () => {
    req.body.orderLinesData = '(function dos() { while(true); })()'

    b2bOrder()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
    expect(next).to.have.callCount(0)
  })

  it('catastrophic regex payload is rejected without being executed', () => {
    req.body.orderLinesData = '/((a+)+)b/.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")'

    b2bOrder()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('sandbox breakout payload is rejected without being executed', () => {
    req.body.orderLinesData = 'this.constructor.constructor("return process")().exit()'

    b2bOrder()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('accepts a single order line as documented in Swagger', () => {
    req.body.orderLinesData = '{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"}'

    b2bOrder()(req, res, next)

    expect(res.status).to.have.callCount(0)
    expect(res.json).to.have.been.calledWith(sinon.match.has('orderNo'))
  })

  it('accepts an array of order lines as documented in Swagger', () => {
    req.body.orderLinesData = '[{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"},{"productId": 13,"quantity": 2000,"customerReference": "PO0000003.4"}]'

    b2bOrder()(req, res, next)

    expect(res.status).to.have.callCount(0)
    expect(res.json).to.have.been.calledWith(sinon.match.has('orderNo'))
  })

  it('rejects JSON that does not match the order line schema', () => {
    req.body.orderLinesData = '{"hello": "world", "foo": 42, "bar": [false, true]}'

    b2bOrder()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects broken JSON', () => {
    req.body.orderLinesData = '{ "productId: 28'

    b2bOrder()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects non-string orderLinesData', () => {
    req.body.orderLinesData = [{ productId: 12, quantity: 1 }]

    b2bOrder()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
  })
})
