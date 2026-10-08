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
import { SecurityAnswerModel } from '../../models/securityAnswer'
import { UserModel } from '../../models/user'

let app: Express
const jsonHeader = { 'content-type': 'application/json' }
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

  void it('POST security answer is forbidden via public API even when authenticated', async () => {
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

  void it('POST security answer cannot be planted anonymously for a user without one', async () => {
    const userRes = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email: 'no.answer@te.st',
        password: '12345'
      })
    assert.equal(userRes.status, 201)

    const plantRes = await request(app)
      .post('/api/SecurityAnswers')
      .set(jsonHeader)
      .send({
        UserId: userRes.body.data.id,
        SecurityQuestionId: 1,
        answer: 'planted'
      })
    assert.equal(plantRes.status, 401)
    assert.equal(await SecurityAnswerModel.count({ where: { UserId: userRes.body.data.id } }), 0)

    const resetRes = await request(app)
      .post('/rest/user/reset-password')
      .set(jsonHeader)
      .send({
        email: 'no.answer@te.st',
        answer: 'planted',
        new: 'hijacked',
        repeat: 'hijacked'
      })
    assert.equal(resetRes.status, 401)
  })
})

void describe('/api/Users registration with security answer', () => {
  void it('POST user stores the security answer bound to the newly created user', async () => {
    const userRes = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email: 'new.user@te.st',
        password: '12345',
        passwordRepeat: '12345',
        securityQuestion: { id: 1, question: 'Your eldest siblings middle name?' },
        securityAnswer: 'Horst'
      })
    assert.equal(userRes.status, 201)

    const answers = await SecurityAnswerModel.findAll({ where: { UserId: userRes.body.data.id } })
    assert.equal(answers.length, 1)
    assert.equal(answers[0].SecurityQuestionId, 1)

    const resetRes = await request(app)
      .post('/rest/user/reset-password')
      .set(jsonHeader)
      .send({
        email: 'new.user@te.st',
        answer: 'Horst',
        new: '54321',
        repeat: '54321'
      })
    assert.equal(resetRes.status, 200)
  })

  void it('POST user with an unknown security question is rejected before the user is created', async () => {
    const res = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email: 'bad.question@te.st',
        password: '12345',
        securityQuestion: { id: 9999 },
        securityAnswer: 'Horst'
      })
    assert.equal(res.status, 400)
    assert.equal(await UserModel.count({ where: { email: 'bad.question@te.st' } }), 0)
  })

  void it('POST user with a security question but an empty answer is rejected', async () => {
    const res = await request(app)
      .post('/api/Users')
      .set(jsonHeader)
      .send({
        email: 'empty.answer@te.st',
        password: '12345',
        securityQuestion: { id: 1 },
        securityAnswer: ' '
      })
    assert.equal(res.status, 400)
    assert.equal(await UserModel.count({ where: { email: 'empty.answer@te.st' } }), 0)
  })
})

void describe('/api/SecurityAnswers/:id', () => {
  void it('GET existing security answer by id is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .get('/api/SecurityAnswers/1')
      .set(authHeader)

    assert.equal(res.status, 401)
  })

  void it('POST security answer for a newly registered user', async () => {
    const userRes = await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'new.user@te.st',
        password: '12345'
      })

    assert.equal(userRes.status, 201)

    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set(authHeader)
      .send({
        UserId: userRes.body.id,
        SecurityQuestionId: 1,
        answer: 'Horst'
      })

    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.data.id, 'number')
    assert.equal(typeof res.body.data.createdAt, 'string')
    assert.equal(typeof res.body.data.updatedAt, 'string')
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
