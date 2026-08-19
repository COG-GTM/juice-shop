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

  it('accepts order lines data as documented in Swagger', () => {
    req.body.orderLinesData = '{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"}'

    b2bOrder()(req, res)

    expect(res.status).to.not.have.been.called
    expect(res.json).to.have.been.calledWithMatch({ orderNo: sinon.match.string })
  })

  it('accepts a request without any order lines data', () => {
    b2bOrder()(req, res)

    expect(res.json).to.have.been.calledWithMatch({ orderNo: sinon.match.string })
  })

  it('rejects broken JSON with a 400 error', () => {
    req.body.orderLinesData = '{ "productId: 28'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects non-string order lines data with a 400 error', () => {
    req.body.orderLinesData = { productId: 12 }

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects an infinite loop payload without executing it', () => {
    req.body.orderLinesData = '(function dos() { while(true); })()'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects a sandbox breakout payload without executing it', () => {
    req.body.orderLinesData = 'this.constructor.constructor("return process")().exit()'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })
})
