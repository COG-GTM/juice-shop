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
import { login } from './helpers/auth'
import { challenges } from '../../data/datacache'
import * as utils from '../../lib/utils'

let app: Express
let existingOrder: { orderId: string, totalPrice: number }

before(async () => {
  const result = await createTestApp()
  app = result.app
  const { token } = await login(app, {
    email: 'admin@' + config.get<string>('application.domain'),
    password: 'admin123'
  })
  const res = await request(app)
    .get('/rest/order-history')
    .set({ Authorization: 'Bearer ' + token })
  existingOrder = res.body.data[0]
}, { timeout: 60000 })

void describe('/rest/track-order/:id', () => {
  void it('GET tracking results for the order id', async () => {
    const res = await request(app)
      .get('/rest/track-order/' + existingOrder.orderId)
    assert.equal(res.status, 200)
    assert.equal(res.body.data.length, 1)
    assert.equal(res.body.data[0].orderId, existingOrder.orderId)
    assert.equal(res.body.data[0].totalPrice, existingOrder.totalPrice)
    assert.ok(res.body.data[0].products.length > 0)
  })

  void it('GET tracking results does not evaluate JavaScript injected into orderId', async () => {
    const res = await request(app)
      .get('/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.length, 1)
    assert.deepEqual(Object.keys(res.body.data[0]), ['orderId'])
  })

  void it('GET tracking results does not match an existing order for an id with characters outside the order id alphabet', async () => {
    const res = await request(app)
      .get('/rest/track-order/' + existingOrder.orderId + '%21')
    assert.equal(res.status, 200)
    assert.equal(res.body.data.length, 1)
    assert.deepEqual(Object.keys(res.body.data[0]), ['orderId'])
    assert.notEqual(res.body.data[0].orderId, existingOrder.orderId)
  })

  void it('GET tracking results reflects the orderId into the not-found placeholder for the Reflected XSS challenge', async () => {
    const res = await request(app)
      .get('/rest/track-order/%3Ciframe%20src%3D%22javascript%3Aalert(%60xss%60)%22%3E')
    assert.equal(res.status, 200)
    assert.equal(res.body.data.length, 1)
    if (utils.isChallengeEnabled(challenges.reflectedXssChallenge)) {
      assert.deepEqual(res.body.data[0], { orderId: '<iframe src="javascript:alert(`xss`)">' })
      assert.equal(challenges.reflectedXssChallenge.solved, true)
    } else {
      assert.deepEqual(res.body.data[0], { orderId: 'iframesrcjavascriptalertxss' })
    }
  })
})
