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

  void it('POST new security answer is forbidden without authentication', async () => {
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

  void it('POST new security answer for an account without one is forbidden without authentication', async () => {
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set({ 'content-type': 'application/json' })
      .send({
        UserId: 2,
        SecurityQuestionId: 1,
        answer: 'Horst'
      })

    assert.equal(res.status, 401)

    const resetRes = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern.kimminich@gmail.com',
        answer: 'Horst',
        new: 'hacked!',
        repeat: 'hacked!'
      })

    assert.equal(resetRes.status, 401)
  })

  void it('POST new security answer ignores UserId from body and uses the authenticated user', async () => {
    const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })
      .send({
        UserId: 9999,
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

  void it('POST new user with security question and answer stores the answer for password reset', async () => {
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

    const resetRes = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'new.user@te.st',
        answer: 'Horst',
        new: '54321',
        repeat: '54321'
      })

    assert.equal(resetRes.status, 200)
  })

  void it('POST new user with unknown security question is rejected and not created', async () => {
    const userRes = await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'unknown.question@te.st',
        password: '12345',
        passwordRepeat: '12345',
        securityQuestion: { id: 99999 },
        securityAnswer: 'Horst'
      })

    assert.equal(userRes.status, 400)

    const retryRes = await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'unknown.question@te.st',
        password: '12345',
        passwordRepeat: '12345',
        securityQuestion: { id: 1 },
        securityAnswer: 'Horst'
      })

    assert.equal(retryRes.status, 201)
  })

  void it('POST security answer for own account without one when logged in', async () => {
    const userRes = await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'answerless.user@te.st',
        password: '12345',
        passwordRepeat: '12345'
      })

    assert.equal(userRes.status, 201)

    const { token } = await login(app, { email: 'answerless.user@te.st', password: '12345' })
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })
      .send({
        UserId: 1,
        SecurityQuestionId: 1,
        answer: 'Horst'
      })

    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.data.id, 'number')
    assert.equal(res.body.data.UserId, userRes.body.data.id)
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
