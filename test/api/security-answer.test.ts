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

  void it('POST new security answer is forbidden via public API', async () => {
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

  void it('POST new security answer is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set(authHeader)
      .send({
        UserId: 4,
        SecurityQuestionId: 1,
        answer: 'pwned'
      })

    assert.equal(res.status, 401)
  })

  void it('password of a user without security answer cannot be reset', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern.kimminich@gmail.com',
        answer: 'pwned',
        new: 'hacked',
        repeat: 'hacked'
      })

    assert.equal(res.status, 401)
  })
})

void describe('/api/SecurityAnswers/:id', () => {
  void it('GET existing security answer by id is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .get('/api/SecurityAnswers/1')
      .set(authHeader)

    assert.equal(res.status, 401)
  })

  void it('security answer submitted during registration enables password reset', async () => {
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

    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'new.user@te.st',
        answer: 'Horst',
        new: '54321',
        repeat: '54321'
      })

    assert.equal(res.status, 200)
  })

  void it('registration with a nonexistent security question is rejected without persisting the user', async () => {
    const payload = {
      email: 'invalid.question@te.st',
      password: '12345',
      passwordRepeat: '12345',
      securityQuestion: { id: 999999 },
      securityAnswer: 'Horst'
    }
    const res = await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send(payload)

    assert.equal(res.status, 400)

    const retryRes = await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({ ...payload, securityQuestion: { id: 1 } })

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
