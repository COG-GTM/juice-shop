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
    res = { json: sinon.spy(), status: sinon.stub().returnsThis() }
  })

  it('accepts order lines as documented in Swagger', () => {
    req.body.cid = 'JS0815DE'
    req.body.orderLinesData = '[{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"},{"productId": 13,"quantity": 2000,"customerReference": "PO0000003.4"}]'

    b2bOrder()(req, res)

    expect(res.status).to.have.callCount(0)
    expect(res.json).to.have.been.calledWith(sinon.match({ cid: 'JS0815DE', orderNo: sinon.match.string, paymentDue: sinon.match.string }))
  })

  it('accepts a single order line object', () => {
    req.body.orderLinesData = '{"productId": 12,"quantity": 10000}'

    b2bOrder()(req, res)

    expect(res.status).to.have.callCount(0)
  })

  it('accepts orders without orderLinesData', () => {
    b2bOrder()(req, res)

    expect(res.status).to.have.callCount(0)
    expect(res.json).to.have.been.calledWith(sinon.match({ orderNo: sinon.match.string }))
  })

  const invalidPayloads: Record<string, unknown> = {
    'broken JSON': '{ "productId: 28',
    'arbitrary JSON without order line fields': '{"hello": "world", "foo": 42, "bar": [false, true]}',
    'an empty array': '[]',
    'a non-integer quantity': '{"productId": 1, "quantity": "10"}',
    'a zero quantity': '{"productId": 1, "quantity": 0}',
    'a non-string value': { productId: 1, quantity: 1 },
    'an infinite loop payload': '(function dos() { while(true); })()',
    'a catastrophic backtracking regex payload': '/((a+)+)b/.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")',
    'a sandbox breakout payload': 'this.constructor.constructor("return process")().exit()',
    'the CVE-2021-23771 notevil escape payload': 'function fn() {}; var constructorProperty = Object.getOwnPropertyDescriptors(fn.__proto__).constructor; var properties = Object.values(constructorProperty); properties.pop(); properties.pop(); properties.pop(); var Func = properties.pop(); Func("return process")().mainModule.require("child_process").execSync("id")'
  }

  for (const [description, orderLinesData] of Object.entries(invalidPayloads)) {
    it(`rejects ${description} with a validation error`, () => {
      req.body.orderLinesData = orderLinesData

      b2bOrder()(req, res)

      expect(res.status).to.have.been.calledWith(400)
      expect(res.json).to.have.been.calledWith(sinon.match({ error: sinon.match.string }))
    })
  }
})
