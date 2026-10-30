/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { b2bOrder, isValidOrderLinesData } from '../../routes/b2bOrder'
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
    req.body.orderLinesData = '[{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"},{"productId": 13,"quantity": 2000,"customerReference": "PO0000003.4"}]'

    b2bOrder()(req, res)

    expect(res.status.called).to.equal(false)
    expect(res.json).to.have.been.calledWithMatch({ orderNo: sinon.match.string, paymentDue: sinon.match.string })
  })

  it('accepts a single order line object', () => {
    req.body.orderLinesData = '{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"}'

    b2bOrder()(req, res)

    expect(res.status.called).to.equal(false)
    expect(res.json).to.have.been.calledWithMatch({ orderNo: sinon.match.string })
  })

  it('accepts a request without order lines data', () => {
    req.body.cid = 'JS0815DE'

    b2bOrder()(req, res)

    expect(res.status.called).to.equal(false)
    expect(res.json).to.have.been.calledWithMatch({ cid: 'JS0815DE', orderNo: sinon.match.string })
  })

  it('rejects broken JSON with a 400 error', () => {
    req.body.orderLinesData = '{ "productId: 28'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
    expect(res.json).to.have.been.calledWithMatch({ error: sinon.match.string })
  })

  it('rejects an infinite loop payload without executing it', () => {
    req.body.orderLinesData = '(function dos() { while(true); })()'

    b2bOrder()(req, res)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects a catastrophic backtracking regex payload without executing it', () => {
    req.body.orderLinesData = '/((a+)+)b/.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")'
    const start = Date.now()

    b2bOrder()(req, res)

    expect(Date.now() - start).to.be.below(500)
    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects a sandbox breakout payload without executing it', () => {
    const exit = sinon.stub(process, 'exit')
    try {
      req.body.orderLinesData = 'this.constructor.constructor("return process")().exit()'

      b2bOrder()(req, res)

      expect(exit.called).to.equal(false)
      expect(res.status).to.have.been.calledWith(400)
    } finally {
      exit.restore()
    }
  })

  describe('isValidOrderLinesData', () => {
    it('rejects non-string values', () => {
      expect(isValidOrderLinesData({ productId: 12, quantity: 1 })).to.equal(false)
      expect(isValidOrderLinesData(['{"productId": 12, "quantity": 1}'])).to.equal(false)
      expect(isValidOrderLinesData(42)).to.equal(false)
    })

    it('rejects JSON that is not an order line or a list of order lines', () => {
      expect(isValidOrderLinesData('{"hello": "world", "foo": 42, "bar": [false, true]}')).to.equal(false)
      expect(isValidOrderLinesData('[]')).to.equal(false)
      expect(isValidOrderLinesData('null')).to.equal(false)
      expect(isValidOrderLinesData('"text"')).to.equal(false)
      expect(isValidOrderLinesData('[[{"productId": 1, "quantity": 1}]]')).to.equal(false)
    })

    it('rejects order lines with missing, non-integer or non-positive productId and quantity', () => {
      expect(isValidOrderLinesData('{"quantity": 1}')).to.equal(false)
      expect(isValidOrderLinesData('{"productId": 1}')).to.equal(false)
      expect(isValidOrderLinesData('{"productId": "1", "quantity": 1}')).to.equal(false)
      expect(isValidOrderLinesData('{"productId": 1, "quantity": 0}')).to.equal(false)
      expect(isValidOrderLinesData('{"productId": 1, "quantity": -5}')).to.equal(false)
      expect(isValidOrderLinesData('{"productId": 1.5, "quantity": 1}')).to.equal(false)
      expect(isValidOrderLinesData('{"productId": 1, "quantity": 1e300}')).to.equal(false)
    })

    it('rejects unexpected keys and wrongly typed optional fields', () => {
      expect(isValidOrderLinesData('{"productId": 1, "quantity": 1, "__proto__": {}}')).to.equal(false)
      expect(isValidOrderLinesData('{"productId": 1, "quantity": 1, "customerReference": 7}')).to.equal(false)
      expect(isValidOrderLinesData('{"productId": 1, "quantity": 1, "customerReference": ["a", 1]}')).to.equal(false)
      expect(isValidOrderLinesData('{"productId": 1, "quantity": 1, "couponCode": {}}')).to.equal(false)
    })

    it('rejects oversized payloads', () => {
      const line = '{"productId": 1, "quantity": 1}'
      expect(isValidOrderLinesData(`[${Array(1001).fill(line).join(',')}]`)).to.equal(false)
      expect(isValidOrderLinesData(`{"productId": 1, "quantity": 1, "couponCode": "${'x'.repeat(100000)}"}`)).to.equal(false)
      expect(isValidOrderLinesData(`[${Array(1000).fill(line).join(',')}]`)).to.equal(true)
    })
  })
})
