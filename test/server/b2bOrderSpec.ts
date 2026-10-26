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
    req = { body: { cid: 'JS0815DE' } }
    res = { json: sinon.spy(), status: sinon.stub() }
    res.status.returns(res)
    next = sinon.spy()
  })

  it('accepts order lines in JSON format as documented in Swagger', () => {
    req.body.orderLinesData = '[{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"},{"productId": 13,"quantity": 2000,"customerReference": "PO0000003.4"}]'

    b2bOrder()(req, res, next)

    expect(res.status).to.not.have.been.called
    expect(res.json).to.have.been.calledWith(sinon.match({ cid: 'JS0815DE', orderNo: sinon.match.string, paymentDue: sinon.match.string }))
  })

  it('accepts a single order line object', () => {
    req.body.orderLinesData = '{"productId": 8, "quantity": 500}'

    b2bOrder()(req, res, next)

    expect(res.status).to.not.have.been.called
  })

  it('accepts an order without orderLinesData', () => {
    b2bOrder()(req, res, next)

    expect(res.status).to.not.have.been.called
    expect(res.json).to.have.been.calledWith(sinon.match({ cid: 'JS0815DE' }))
  })

  it('rejects JavaScript code instead of evaluating it', () => {
    req.body.orderLinesData = '(function dos() { while(true); })()'

    b2bOrder()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects sandbox breakout payloads', () => {
    req.body.orderLinesData = 'this.constructor.constructor("return process")().exit()'

    b2bOrder()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects broken JSON', () => {
    req.body.orderLinesData = '{ "productId: 28'

    b2bOrder()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects JSON not matching the order line schema', () => {
    for (const data of ['{"hello": "world"}', '[]', '42', '{"productId": "12", "quantity": 1}', '{"productId": 12, "quantity": 0}', '[{"productId": 12, "quantity": 1, "customerReference": {}}]']) {
      res.status.resetHistory()
      req.body.orderLinesData = data

      b2bOrder()(req, res, next)

      expect(res.status, data).to.have.been.calledWith(400)
    }
  })

  it('rejects non-string orderLinesData', () => {
    req.body.orderLinesData = { productId: 12, quantity: 1 }

    b2bOrder()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
  })
})
