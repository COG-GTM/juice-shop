/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import * as security from '../../lib/insecurity'
import { createTestApp } from './helpers/setup'

let app: Express
const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/b2b/v2/orders', () => {
  for (const [name, payload] of [
    ['endless loop', '(function dos() { while(true); })()'],
    ['busy spinning regex', '/((a+)+)b/.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")'],
    ['sandbox breakout', 'this.constructor.constructor("return process")().exit()'],
    ['memory exhaustion', 'const a = []; while (true) a.push("x".repeat(1e7))']
  ]) {
    void it(`POST ${name} payload in "orderLinesData" is rejected as invalid JSON`, async () => {
      const res = await request(app)
        .post('/b2b/v2/orders')
        .set(authHeader)
        .send({ orderLinesData: payload })

      assert.equal(res.status, 400)
    })
  }

  void it('POST new B2B order accepts valid JSON in "orderLinesData"', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .set(authHeader)
      .send({
        cid: 'JS0815DE',
        orderLinesData: '[{"productId": 12,"quantity": 10000,"customerReference": "PO0000001.2"}]'
      })

    assert.equal(res.status, 200)
    assert.equal(res.body.cid, 'JS0815DE')
  })

  void it('POST new B2B order is forbidden without authorization token', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .send({})

    assert.equal(res.status, 401)
  })

  void it('POST new B2B order accepts arbitrary valid JSON', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .set(authHeader)
      .send({
        foo: 'bar',
        test: 42
      })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    if (res.body.cid !== undefined) assert.equal(typeof res.body.cid, 'string')
    assert.equal(typeof res.body.orderNo, 'string')
    assert.equal(typeof res.body.paymentDue, 'string')
  })

  void it('POST new B2B order has passed "cid" in response', async () => {
    const res = await request(app)
      .post('/b2b/v2/orders')
      .set(authHeader)
      .send({
        cid: 'test'
      })

    assert.equal(res.status, 200)
    assert.equal(res.body.cid, 'test')
  })
})
