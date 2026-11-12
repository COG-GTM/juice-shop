/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import * as security from '../../lib/insecurity'
import { login } from './helpers/auth'
import { SecurityAnswerModel } from '../../models/securityAnswer'

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

  void it('POST new security answer is rejected for anonymous callers', async () => {
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set({ 'content-type': 'application/json' })
      .send({
        UserId: 1,
        SecurityQuestionId: 1,
        answer: 'Horst'
      })

    assert.equal(res.status, 401)
  })

  void it('POST new security answer stores it for the logged-in user instead of the UserId in the body', async () => {
    const email = 'answer.owner@te.st'
    const password = 'ownerPass1'
    const userRes = await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({ email, password, passwordRepeat: password })
    assert.equal(userRes.status, 201)

    const victimRes = await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'answer.victim@te.st', password: 'victimPass1', passwordRepeat: 'victimPass1' })
    assert.equal(victimRes.status, 201)
    const victim = { id: victimRes.body.data.id }
    assert.equal(await SecurityAnswerModel.findOne({ where: { UserId: victim.id } }), null)

    const { token } = await login(app, { email, password })
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })
      .send({
        UserId: victim.id,
        SecurityQuestionId: 1,
        answer: 'Horst'
      })

    assert.equal(res.status, 201)
    assert.equal(res.body.data.UserId, userRes.body.data.id)
    assert.equal(await SecurityAnswerModel.findOne({ where: { UserId: victim.id } }), null)
  })

  void it('POST second security answer for logged-in user fails from unique constraint', async () => {
    const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })
      .send({
        SecurityQuestionId: 1,
        answer: 'Horst'
      })

    assert.equal(res.status, 400)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.message, 'Validation error')
  })
})

void describe('/api/SecurityAnswers/:id', () => {
  void it('GET existing security answer by id is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .get('/api/SecurityAnswers/1')
      .set(authHeader)

    assert.equal(res.status, 401)
  })

  void it('POST /api/Users stores the security answer for the newly registered user', async () => {
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

    const resetRes = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'new.user@te.st', answer: 'Horst', new: '54321', repeat: '54321' })

    assert.equal(resetRes.status, 200)
  })

  void it('POST /api/Users with an unknown security question is rejected without creating the user', async () => {
    const user = {
      email: 'unknown.question@te.st',
      password: '12345',
      passwordRepeat: '12345',
      securityQuestion: { id: 999999 },
      securityAnswer: 'Horst'
    }
    const failedRes = await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send(user)

    assert.equal(failedRes.status, 400)

    const retryRes = await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({ ...user, securityQuestion: { id: 1 } })

    assert.equal(retryRes.status, 201)
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
