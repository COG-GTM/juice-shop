/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import * as security from '../../lib/insecurity'

let app: Express
const jsonHeader = { 'content-type': 'application/json' }
const authHeader = { Authorization: `Bearer ${security.authorize()}`, ...jsonHeader }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function loginHeader (email: string, password: string) {
  const { token } = await login(app, { email, password })
  return { Authorization: `Bearer ${token}`, ...jsonHeader }
}

void describe('/api/SecurityAnswers', () => {
  void it('GET all security answers is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .get('/api/SecurityAnswers')
      .set(authHeader)

    assert.equal(res.status, 401)
  })

  void it('POST new security answer anonymously is forbidden', async () => {
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set(jsonHeader)
      .send({
        UserId: 1,
        SecurityQuestionId: 1,
        answer: 'Horst'
      })

    assert.equal(res.status, 401)
  })

  void it('POST new security answer with token of unknown session is forbidden', async () => {
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set(authHeader)
      .send({
        UserId: 1,
        SecurityQuestionId: 1,
        answer: 'Horst'
      })

    assert.equal(res.status, 401)
  })

  void it('POST new security answer for user who already has one fails from unique constraint', async () => {
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set(await loginHeader('jim@juice-sh.op', 'ncc-1701'))
      .send({
        UserId: 1,
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

  void it('POST security answer is always stored for the logged-in user regardless of UserId', async () => {
    const userRes = await register(app, { email: 'new.user@te.st', password: '12345' })

    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set(await loginHeader('new.user@te.st', '12345'))
      .send({
        UserId: 1,
        SecurityQuestionId: 1,
        answer: 'Horst'
      })

    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.data.id, 'number')
    assert.equal(res.body.data.UserId, userRes.body.data.id)
    assert.equal(typeof res.body.data.createdAt, 'string')
    assert.equal(typeof res.body.data.updatedAt, 'string')
  })

  void it('POST /api/Users stores the security answer chosen during registration', async () => {
    const userRes = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email: 'answer.on.register@te.st',
        password: '12345',
        passwordRepeat: '12345',
        securityQuestion: { id: 1 },
        securityAnswer: 'Horst'
      })

    assert.equal(userRes.status, 201)

    const resetRes = await request(app)
      .post('/rest/user/reset-password')
      .set(jsonHeader)
      .send({
        email: 'answer.on.register@te.st',
        answer: 'Horst',
        new: '54321',
        repeat: '54321'
      })

    assert.equal(resetRes.status, 200)
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
