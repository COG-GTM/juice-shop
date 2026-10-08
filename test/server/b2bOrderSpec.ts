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
    res = { json: sinon.spy(), status: sinon.stub() }
    res.status.returns(res)
    next = sinon.spy()
  })

  it('accepts JSON order lines as documented in Swagger', () => {
    req.body.orderLinesData = '[{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"},{"productId": 13,"quantity": 2000,"customerReference": "PO0000003.4"}]'

    b2bOrder()(req, res, next)

    expect(res.status).to.not.have.been.called
    expect(res.json).to.have.been.calledWith(sinon.match.has('orderNo'))
  })

  it('accepts a single JSON order line object', () => {
    req.body.orderLinesData = '{"hello": "world", "foo": 42, "bar": [false, true]}'

    b2bOrder()(req, res, next)

    expect(res.status).to.not.have.been.called
    expect(res.json).to.have.been.calledWith(sinon.match.has('orderNo'))
  })

  it('accepts requests without orderLinesData', () => {
    b2bOrder()(req, res, next)

    expect(res.status).to.not.have.been.called
    expect(res.json).to.have.been.calledWith(sinon.match.has('orderNo'))
  })

  it('rejects broken JSON', () => {
    req.body.orderLinesData = '{ "productId: 28'

    b2bOrder()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects JavaScript code instead of evaluating it', () => {
    req.body.orderLinesData = 'this.constructor.constructor("return process")().exit()'

    b2bOrder()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects infinite loop payload immediately', () => {
    req.body.orderLinesData = '(function dos() { while(true); })()'

    b2bOrder()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects JSON that is not an object or array of objects', () => {
    for (const payload of ['42', '"text"', 'null', '[1, 2]', '[[{}]]']) {
      res.status.resetHistory()
      req.body.orderLinesData = payload

      b2bOrder()(req, res, next)

      expect(res.status).to.have.been.calledWith(400)
    }
  })

  it('rejects non-string orderLinesData', () => {
    req.body.orderLinesData = { productId: 1 }

    b2bOrder()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
  })
})
