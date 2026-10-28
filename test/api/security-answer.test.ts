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

  void it('POST new security answer is forbidden via public API when not authenticated', async () => {
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

  void it('POST new security answer is forbidden via public API even when authenticated', async () => {
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

  void it('POST security answer for a user registered without one is forbidden', async () => {
    const userRes = await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'no.answer@te.st',
        password: '12345'
      })

    assert.equal(userRes.status, 201)

    const answerRes = await request(app)
      .post('/api/SecurityAnswers')
      .set({ 'content-type': 'application/json' })
      .send({
        UserId: userRes.body.data.id,
        SecurityQuestionId: 1,
        answer: 'mallory'
      })

    assert.equal(answerRes.status, 401)

    const resetRes = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'no.answer@te.st',
        answer: 'mallory',
        new: 'hacked',
        repeat: 'hacked'
      })

    assert.equal(resetRes.status, 401)
  })

  void it('registering a user with a security question stores the answer', async () => {
    const userRes = await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'with.answer@te.st',
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
        email: 'with.answer@te.st',
        answer: 'Horst',
        new: 'abcde',
        repeat: 'abcde'
      })

    assert.equal(resetRes.status, 200)
  })
})

void describe('/api/SecurityAnswers/:id', () => {
  void it('GET existing security answer by id is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .get('/api/SecurityAnswers/1')
      .set(authHeader)

    assert.equal(res.status, 401)
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
