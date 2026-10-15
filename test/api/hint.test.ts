/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { HintModel } from '../../models/hint'
import { login } from './helpers/auth'

let app: Express
let jsonHeader: { Authorization: string, 'content-type': string }

before(async () => {
  const result = await createTestApp()
  app = result.app
  const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
  jsonHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
}, { timeout: 60000 })

void describe('/api/Hints/:id', () => {
  void it('PUT by anonymous user is denied', async () => {
    const res = await request(app)
      .put('/api/Hints/4')
      .set('content-type', 'application/json')
      .send({ unlocked: true })
    assert.equal(res.status, 401)
    const hint = await HintModel.findByPk(4)
    assert.equal(hint?.unlocked, false)
  })

  void it('PUT unlocks a hint', async () => {
    const res = await request(app)
      .put('/api/Hints/1')
      .set(jsonHeader)
      .send({ unlocked: true })
    assert.equal(res.status, 200)
    assert.equal(res.body.data.unlocked, true)
  })

  void it('PUT cannot change hint text', async () => {
    const original = await HintModel.findByPk(2)
    const res = await request(app)
      .put('/api/Hints/2')
      .set(jsonHeader)
      .send({ text: 'pwned', ChallengeId: 1 })
    assert.equal(res.status, 400)
    const hint = await HintModel.findByPk(2)
    assert.equal(hint?.text, original?.text)
    assert.equal(hint?.ChallengeId, original?.ChallengeId)
  })

  void it('PUT ignores attributes other than unlocked', async () => {
    const original = await HintModel.findByPk(3)
    const res = await request(app)
      .put('/api/Hints/3')
      .set(jsonHeader)
      .send({ unlocked: true, text: 'pwned', order: 99 })
    assert.equal(res.status, 200)
    const hint = await HintModel.findByPk(3)
    assert.equal(hint?.text, original?.text)
    assert.equal(hint?.order, original?.order)
    assert.equal(hint?.unlocked, true)
  })
})
