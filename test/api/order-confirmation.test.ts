/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import zlib from 'node:zlib'
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import jwt from 'jsonwebtoken'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import * as security from '../../lib/insecurity'

let app: Express
let jimToken: string
let jimBasketId: number
let benderToken: string
let orderId: string

async function checkoutJim () {
  const item = await request(app)
    .post('/api/BasketItems')
    .set({ Authorization: 'Bearer ' + jimToken, 'content-type': 'application/json' })
    .send({ BasketId: jimBasketId, ProductId: 1, quantity: 1 })
  assert.equal(item.status, 200)
  const checkout = await request(app)
    .post(`/rest/basket/${jimBasketId}/checkout`)
    .set({ Authorization: 'Bearer ' + jimToken, 'content-type': 'application/json' })
  assert.equal(checkout.status, 200)
  return checkout.body.orderConfirmation as string
}

function pdfText (pdf: Buffer) {
  const raw = pdf.toString('latin1')
  let text = ''
  for (const match of raw.matchAll(/stream\r?\n([\s\S]*?)endstream/g)) {
    let content: string
    try {
      content = zlib.inflateSync(Buffer.from(match[1], 'latin1')).toString('latin1')
    } catch {
      continue
    }
    for (const line of content.matchAll(/\[(.*?)\] TJ/g)) {
      text += [...line[1].matchAll(/<([0-9a-f]*)>/g)].map(hex => Buffer.from(hex[1], 'hex').toString('latin1')).join('') + '\n'
    }
  }
  return text
}

function binaryParser (res: any, callback: (err: Error | null, body: Buffer) => void) {
  const chunks: Buffer[] = []
  res.on('data', (chunk: Buffer) => chunks.push(chunk))
  res.on('end', () => { callback(null, Buffer.concat(chunks)) })
}

function assertPopulatedConfirmation (pdf: Buffer) {
  const text = pdfText(pdf)
  assert.ok(text.includes('jim@juice-sh.op'), text)
  assert.ok(text.includes('Apple Juice (1000ml)'), text)
}

// Other API test files run in parallel and clear orders/**/*.pdf on startup, so a fresh order is placed right before each download attempt
async function downloadFreshOrderConfirmation (send: (req: request.Test) => request.Test) {
  for (let attempt = 1; ; attempt++) {
    const freshOrderId = await checkoutJim()
    const res = await send(request(app).get(`/rest/order-confirmation/${freshOrderId}`))
    if (res.status !== 404 || attempt === 3) return res
  }
}

before(async () => {
  const result = await createTestApp()
  app = result.app

  const jim = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
  jimToken = jim.token
  jimBasketId = jim.bid
  benderToken = (await login(app, { email: 'bender@juice-sh.op', password: 'OhG0dPlease1nsertLiquor!' })).token

  orderId = await checkoutJim()
}, { timeout: 60000 })

void describe('order confirmation PDFs', () => {
  void it('are not listed in the public /ftp directory', async () => {
    const res = await request(app).get('/ftp')
    assert.equal(res.status, 404)
    assert.ok(!res.text.includes('order_'))
  })

  void it('cannot be downloaded from the public /ftp directory', async () => {
    const res = await request(app).get(`/ftp/order_${orderId}.pdf`)
    assert.equal(res.status, 404)
  })
})

void describe('/rest/order-confirmation/:orderId', () => {
  void it('GET without authentication is denied', async () => {
    const res = await request(app).get(`/rest/order-confirmation/${orderId}`)
    assert.equal(res.status, 401)
    assert.equal(res.headers['cache-control'], 'private, no-store')
  })

  void it('GET another customer\'s order confirmation is not found', async () => {
    const res = await request(app)
      .get(`/rest/order-confirmation/${orderId}`)
      .set('Authorization', 'Bearer ' + benderToken)
    assert.equal(res.status, 404)
  })

  void it('GET own order confirmation with bearer token returns the PDF', async () => {
    const res = await downloadFreshOrderConfirmation(req => req.set('Authorization', 'Bearer ' + jimToken).buffer(true).parse(binaryParser))
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/pdf'))
    assert.equal(res.headers['cache-control'], 'private, no-store')
    assertPopulatedConfirmation(res.body)
  })

  void it('GET own order confirmation with token cookie returns the PDF', async () => {
    const res = await downloadFreshOrderConfirmation(req => req.set('Cookie', 'token=' + jimToken).buffer(true).parse(binaryParser))
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/pdf'))
    assertPopulatedConfirmation(res.body)
  })

  void it('GET with a validly signed token that was never issued by a login is denied', async () => {
    const sessionlessToken = security.authorize({ data: (security.decode(jimToken) as any).data })
    const res = await request(app)
      .get(`/rest/order-confirmation/${orderId}`)
      .set('Authorization', 'Bearer ' + sessionlessToken)
    assert.equal(res.status, 401)
  })

  void it('GET with a registered but unverifiable token is denied', async () => {
    const forgedToken = jwt.sign({ data: { id: 2 } }, crypto.randomBytes(32).toString('hex'))
    security.authenticatedUsers.put(forgedToken, { data: { id: 2 } } as any)
    const res = await request(app)
      .get(`/rest/order-confirmation/${orderId}`)
      .set('Authorization', 'Bearer ' + forgedToken)
    assert.equal(res.status, 401)
  })

  void it('GET with a registered unsigned token is denied', async () => {
    const b64 = (value: string) => Buffer.from(value).toString('base64url')
    const unsignedToken = `${b64('{"alg":"none","typ":"JWT"}')}.${b64('{"data":{"id":2}}')}.`
    security.authenticatedUsers.put(unsignedToken, { data: { id: 2 } } as any)
    const res = await request(app)
      .get(`/rest/order-confirmation/${orderId}`)
      .set('Authorization', 'Bearer ' + unsignedToken)
    assert.equal(res.status, 401)
  })

  void it('GET with a malformed order id is not found', async () => {
    const res = await request(app)
      .get('/rest/order-confirmation/..%2F..%2Fpackage.json')
      .set('Authorization', 'Bearer ' + jimToken)
    assert.equal(res.status, 404)
  })
})
