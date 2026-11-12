/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, mock } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import PDFDocument from 'pdfkit'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express
let authHeader: { Authorization: string, 'content-type': string }
let basketId: number

before(async () => {
  const result = await createTestApp()
  app = result.app

  const { token, bid } = await login(app, {
    email: 'jim@juice-sh.op',
    password: 'ncc-1701'
  })
  authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
  basketId = bid
}, { timeout: 60000 })

void describe('/rest/basket/:id/checkout order confirmation PDF', () => {
  void it('prints line item prices and totals with two decimals', async () => {
    const itemRes = await request(app)
      .post('/api/BasketItems')
      .set(authHeader)
      .send({ BasketId: basketId, ProductId: 2, quantity: 5 })
    assert.equal(itemRes.status, 200)

    const text = mock.method(PDFDocument.prototype, 'text')
    try {
      const res = await request(app).post(`/rest/basket/${basketId}/checkout`).set(authHeader)
      assert.equal(res.status, 200)
    } finally {
      text.mock.restore()
    }

    const lines = text.mock.calls.map((call: { arguments: unknown[] }) => String(call.arguments[0]))
    assert.ok(lines.includes('5x Orange Juice (1000ml) ea. 2.99 = 14.95¤'), `Unexpected PDF lines:\n${lines.join('\n')}`)
  })
})
