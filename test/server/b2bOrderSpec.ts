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

  it('infinite loop payload is rejected without being evaluated', () => {
    req.body.orderLinesData = '(function dos() { while(true); })()'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('sandbox breakout payload is rejected without being evaluated', () => {
    req.body.orderLinesData = 'this.constructor.constructor("return process")().exit()'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('non-string orderLinesData is rejected', () => {
    req.body.orderLinesData = { productId: 12 }

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('JSON as documented in Swagger is accepted', () => {
    req.body.orderLinesData = '{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"}'
    req.body.cid = 'JS0815DE'

    b2bOrder()(req, res)

    expect(res.status).to.not.have.been.called
    expect(res.json).to.have.been.calledWithMatch({ cid: 'JS0815DE' })
  })

  it('arbitrary JSON is accepted', () => {
    req.body.orderLinesData = '{"hello": "world", "foo": 42, "bar": [false, true]}'

    b2bOrder()(req, res)

    expect(res.status).to.not.have.been.called
    expect(res.json).to.have.been.calledWithMatch({ orderNo: sinon.match.string, paymentDue: sinon.match.string })
  })

  it('broken JSON is rejected', () => {
    req.body.orderLinesData = '{ "productId: 28'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })
})
