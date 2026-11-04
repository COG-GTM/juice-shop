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

  it('accepts order lines as documented in Swagger', () => {
    req.body.orderLinesData = '[{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"},{"productId": 13,"quantity": 2000,"customerReference": "PO0000003.4"}]'

    b2bOrder()(req, res)

    expect(res.status).to.not.have.been.called
    expect(res.json).to.have.been.calledWith(sinon.match.has('orderNo'))
  })

  it('accepts a single order line object', () => {
    req.body.orderLinesData = '{"productId": 12,"quantity": 10000}'

    b2bOrder()(req, res)

    expect(res.status).to.not.have.been.called
  })

  it('accepts requests without orderLinesData', () => {
    req.body.cid = 'test'

    b2bOrder()(req, res)

    expect(res.status).to.not.have.been.called
    expect(res.json).to.have.been.calledWith(sinon.match({ cid: 'test' }))
  })

  it('rejects JavaScript code instead of evaluating it', () => {
    req.body.orderLinesData = '(function dos() { while(true); })()'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects sandbox breakout payloads', () => {
    req.body.orderLinesData = 'this.constructor.constructor("return process")().exit()'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects broken JSON', () => {
    req.body.orderLinesData = '{ "productId: 28'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects JSON that is not made of order lines', () => {
    req.body.orderLinesData = '{"hello": "world", "foo": 42, "bar": [false, true]}'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects order lines with a non-positive quantity', () => {
    req.body.orderLinesData = '[{"productId": 1, "quantity": 0}]'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects non-string orderLinesData', () => {
    req.body.orderLinesData = [{ productId: 1, quantity: 1 }]

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })
})
