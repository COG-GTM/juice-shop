/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import * as security from '../../lib/insecurity'
import { SecurityAnswerModel } from '../../models/securityAnswer'
import { UserModel } from '../../models/user'

let app: Express
const authHeader = { Authorization: `Bearer ${security.authorize()}`, 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/api/SecurityAnswers', () => {
  void it('GET all security answers is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .get('/api/SecurityAnswers')
      .set(authHeader)

    assert.equal(res.status, 401)
  })

  void it('POST new security answer is denied without authentication', async () => {
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set({ 'content-type': 'application/json' })
      .send({
        UserId: 4,
        SecurityQuestionId: 1,
        answer: 'pwned'
      })

    assert.equal(res.status, 401)
  })

  void it('POST new security answer for user who already has one fails from unique constraint', async () => {
    const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })
      .send({
        UserId: 1,
        SecurityQuestionId: 1,
        answer: 'Horst'
      })

    assert.equal(res.status, 400)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.message, 'Validation error')
  })

  void it('POST new security answer is stored for the authenticated user regardless of given UserId', async () => {
    const { token, umail } = await login(app, { email: 'testing@juice-sh.op', password: 'IamUsedForTesting' })
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })
      .send({
        UserId: 3,
        SecurityQuestionId: 1,
        answer: 'Horst'
      })

    assert.equal(res.status, 201)
    const answer = await SecurityAnswerModel.findOne({ include: [{ model: UserModel, where: { email: umail } }] })
    assert.equal(answer?.UserId, res.body.data.UserId)
    assert.notEqual(res.body.data.UserId, 3)
  })
})

void describe('/api/SecurityAnswers/:id', () => {
  void it('GET existing security answer by id is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .get('/api/SecurityAnswers/1')
      .set(authHeader)

    assert.equal(res.status, 401)
  })

  void it('POST /api/Users stores the security answer given during registration', async () => {
    const userRes = await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'new.user@te.st',
        password: '12345',
        passwordRepeat: '12345',
        securityQuestion: { id: 1 },
        securityAnswer: 'Horst'
      })

    assert.equal(userRes.status, 201)

    const answer = await SecurityAnswerModel.findOne({ where: { UserId: userRes.body.data.id } })
    assert.ok(answer)
    assert.equal(answer.SecurityQuestionId, 1)
    assert.equal(answer.answer, security.hmac('Horst'))
  })

  void it('POST /api/Users with an unknown security question is rejected and creates no user', async () => {
    const userRes = await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'invalid.question@te.st',
        password: '12345',
        passwordRepeat: '12345',
        securityQuestion: { id: 4711 },
        securityAnswer: 'Horst'
      })

    assert.equal(userRes.status, 400)
    assert.equal(await UserModel.findOne({ where: { email: 'invalid.question@te.st' }, paranoid: false }), null)
  })

  void it('PUT update existing security answer is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .put('/api/SecurityAnswers/1')
      .set(authHeader)
      .send({
        answer: 'Blurp'
      })

    assert.equal(res.status, 401)
  })

  void it('DELETE existing security answer is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .delete('/api/SecurityAnswers/1')
      .set(authHeader)

    assert.equal(res.status, 401)
  })
})
