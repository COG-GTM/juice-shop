/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import * as security from '../../lib/insecurity'

let app: Express
let jimHeader: { Authorization: string, 'content-type': string }
let benderHeader: { Authorization: string, 'content-type': string }
let lookalikeHeader: { Authorization: string, 'content-type': string }
let orderId: string

before(async () => {
  const result = await createTestApp()
  app = result.app

  const jim = await login(app, { email: 'jim@' + config.get<string>('application.domain'), password: 'ncc-1701' })
  jimHeader = { Authorization: 'Bearer ' + jim.token, 'content-type': 'application/json' }
  const bender = await login(app, { email: 'bender@' + config.get<string>('application.domain'), password: 'OhG0dPlease1nsertLiquor!' })
  benderHeader = { Authorization: 'Bearer ' + bender.token, 'content-type': 'application/json' }

  const lookalikeEmail = findLookalikeEmail('jim@' + config.get<string>('application.domain'))
  await register(app, { email: lookalikeEmail, password: 'lookalike123' })
  const lookalike = await login(app, { email: lookalikeEmail, password: 'lookalike123' })
  lookalikeHeader = { Authorization: 'Bearer ' + lookalike.token, 'content-type': 'application/json' }

  const res = await request(app).post('/rest/basket/2/checkout').set(jimHeader)
  assert.equal(res.status, 200)
  orderId = res.body.orderConfirmation
}, { timeout: 60000 })

function findLookalikeEmail (email: string) {
  const vowels = 'aeiouAEIOU'
  const positions = [...email].flatMap((c, i) => vowels.includes(c) ? [i] : [])
  const prefix = security.hash(email).slice(0, 4)
  for (let n = 1; n < vowels.length ** positions.length; n++) {
    const chars = [...email]
    positions.forEach((pos, i) => { chars[pos] = vowels[Math.floor(n / vowels.length ** i) % vowels.length] })
    const candidate = chars.join('')
    if (candidate.toLowerCase() !== email.toLowerCase() && security.hash(candidate).startsWith(prefix)) return candidate
  }
  throw new Error(`No email with the same masked form and hash prefix as ${email} found`)
}

void describe('order confirmation PDF', () => {
  void it('is not listed in the public /ftp folder', async () => {
    const res = await request(app).get('/ftp')
    assert.equal(res.status, 200)
    assert.ok(!res.text.includes(orderId))
    assert.ok(!res.text.includes('order_'))
  })

  void it('cannot be downloaded from the public /ftp folder', async () => {
    const res = await request(app).get(`/ftp/order_${orderId}.pdf`)
    assert.notEqual(res.status, 200)
  })

  void it('GET confirmation requires authentication', async () => {
    const res = await request(app).get(`/rest/order-history/${orderId}/confirmation`)
    assert.equal(res.status, 401)
  })

  void it('GET own confirmation returns the PDF', async () => {
    const res = await request(app).get(`/rest/order-history/${orderId}/confirmation`).set(jimHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/pdf'))
  })

  void it('GET confirmation of another customer is not found', async () => {
    const res = await request(app).get(`/rest/order-history/${orderId}/confirmation`).set(benderHeader)
    assert.equal(res.status, 404)
  })

  void it('GET confirmation of another customer with the same masked email and hash prefix is not found', async () => {
    const res = await request(app).get(`/rest/order-history/${orderId}/confirmation`).set(lookalikeHeader)
    assert.equal(res.status, 404)
  })

  void it('GET confirmation with malformed order id is not found', async () => {
    const res = await request(app).get('/rest/order-history/..%2F..%2Fpackage.json/confirmation').set(jimHeader)
    assert.equal(res.status, 404)
  })
})
