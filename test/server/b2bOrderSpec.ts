/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
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

  it('does not import notevil or node:vm', () => {
    const source = fs.readFileSync(path.resolve(__dirname, '../../routes/b2bOrder.ts'), 'utf8')
    expect(source).to.not.match(/notevil/)
    expect(source).to.not.match(/from ['"](node:)?vm['"]/)
  })

  it('rejects infinite loop payload with 400 without evaluating it', () => {
    req.body.orderLinesData = '(function dos() { while(true); })()'

    b2bOrder()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
    expect(next).to.have.not.been.called
  })

  it('rejects sandbox breakout payload with 400', () => {
    req.body.orderLinesData = 'this.constructor.constructor("return process")().exit()'

    b2bOrder()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('accepts JSON order lines as documented in Swagger', () => {
    req.body.cid = 'JS0815DE'
    req.body.orderLinesData = '[{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"},{"productId": 13,"quantity": 2000,"customerReference": "PO0000003.4"}]'

    b2bOrder()(req, res, next)

    expect(res.status).to.have.not.been.called
    expect(res.json).to.have.been.calledWith(sinon.match({ cid: 'JS0815DE' }))
  })

  it('accepts a single JSON order line object', () => {
    req.body.orderLinesData = '{"productId": 8, "quantity": 500}'

    b2bOrder()(req, res, next)

    expect(res.status).to.have.not.been.called
    expect(res.json).to.have.been.calledWith(sinon.match.has('orderNo'))
  })

  it('rejects JSON not matching the order line schema with 400', () => {
    req.body.orderLinesData = '{"hello": "world", "foo": 42, "bar": [false, true]}'

    b2bOrder()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects broken JSON with 400', () => {
    req.body.orderLinesData = '{ "productId: 28'

    b2bOrder()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('rejects non-string orderLinesData with 400', () => {
    req.body.orderLinesData = { productId: 8, quantity: 1 }

    b2bOrder()(req, res, next)

    expect(res.status).to.have.been.calledWith(400)
  })

  it('accepts orders without orderLinesData', () => {
    req.body.cid = 'test'

    b2bOrder()(req, res, next)

    expect(res.status).to.have.not.been.called
    expect(res.json).to.have.been.calledWith(sinon.match({ cid: 'test' }))
  })
})
