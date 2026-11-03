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
    res = { json: sinon.spy() }
    res.status = sinon.stub().returns(res)
  })

  it('rejects infinite loop payload without evaluating it', () => {
    req.body.orderLinesData = '(function dos() { while(true); })()'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects catastrophic backtracking regex payload without evaluating it', () => {
    req.body.orderLinesData = '/((a+)+)b/.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects sandbox breakout payload without evaluating it', () => {
    req.body.orderLinesData = 'this.constructor.constructor("return process")().exit()'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects non-string orderLinesData', () => {
    req.body.orderLinesData = { productId: 12 }

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('accepts JSON as documented in Swagger', () => {
    req.body.cid = 'JS0815DE'
    req.body.orderLinesData = '[{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"}]'

    b2bOrder()(req, res)

    expect(res.status).to.have.callCount(0)
    expect(res.json).to.have.been.calledWithMatch({ cid: 'JS0815DE' })
  })

  it('accepts arbitrary JSON', () => {
    req.body.orderLinesData = '{"hello": "world", "foo": 42, "bar": [false, true]}'

    b2bOrder()(req, res)

    expect(res.status).to.have.callCount(0)
    expect(res.json).to.have.callCount(1)
  })

  it('accepts orders without orderLinesData', () => {
    b2bOrder()(req, res)

    expect(res.status).to.have.callCount(0)
    expect(res.json).to.have.callCount(1)
  })

  it('rejects broken JSON', () => {
    req.body.orderLinesData = '{ "productId: 28'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })
})
