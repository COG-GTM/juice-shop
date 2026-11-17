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
    req = { body: { cid: 'JS0815DE' } }
    res = { json: sinon.spy(), status: sinon.stub() }
    res.status.returns(res)
  })

  it('accepts a single order line as documented in Swagger', () => {
    req.body.orderLinesData = '{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"}'

    b2bOrder()(req, res)

    expect(res.status.called).to.equal(false)
    expect(res.json).to.have.been.calledWith(sinon.match({ cid: 'JS0815DE' }))
  })

  it('accepts multiple order lines as documented in Swagger', () => {
    req.body.orderLinesData = '[{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"},{"productId": 13,"quantity": 2000,"customerReference": "PO0000003.4"}]'

    b2bOrder()(req, res)

    expect(res.status.called).to.equal(false)
    expect(res.json).to.have.been.calledWith(sinon.match({ cid: 'JS0815DE' }))
  })

  it('accepts an order without order lines data', () => {
    b2bOrder()(req, res)

    expect(res.status.called).to.equal(false)
    expect(res.json).to.have.been.calledWith(sinon.match({ cid: 'JS0815DE' }))
  })

  it('rejects JSON that does not match the order line schema', () => {
    req.body.orderLinesData = '{"hello": "world", "foo": 42, "bar": [false, true]}'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects broken JSON', () => {
    req.body.orderLinesData = '{ "productId: 28'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects JavaScript code instead of evaluating it', () => {
    req.body.orderLinesData = '(function dos() { while(true); })()'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects non-string order lines data', () => {
    req.body.orderLinesData = { productId: 12, quantity: 1 }

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })
})
