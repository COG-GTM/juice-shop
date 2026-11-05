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

  void it('POST new security answer is forbidden when not logged in', async () => {
    const userRes = await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'victim.user@te.st', password: '12345' })
    assert.equal(userRes.status, 201)

    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set({ 'content-type': 'application/json' })
      .send({
        UserId: userRes.body.id,
        SecurityQuestionId: 1,
        answer: 'x'
      })
    assert.equal(res.status, 401)

    const resetRes = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'victim.user@te.st', answer: 'x', new: 'pwned', repeat: 'pwned' })
    assert.equal(resetRes.status, 401)
  })

  void it('POST new security answer for logged in user who already has one fails from unique constraint', async () => {
    const { token } = await login(app, { email: 'jim@' + config.get<string>('application.domain'), password: 'ncc-1701' })

    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      .send({
        SecurityQuestionId: 1,
        answer: 'Horst'
      })

    assert.equal(res.status, 400)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.message, 'Validation error')
  })

  void it('POST new security answer always stores it for the logged in user regardless of UserId in body', async () => {
    const adminRes = await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'other.victim@te.st', password: '12345' })
    assert.equal(adminRes.status, 201)

    await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'attacker@te.st', password: '12345' })
      .expect(201)
    const { token } = await login(app, { email: 'attacker@te.st', password: '12345' })

    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
      .send({
        UserId: adminRes.body.id,
        SecurityQuestionId: 1,
        answer: 'x'
      })
    assert.equal(res.status, 201)
    assert.notEqual(res.body.data.UserId, adminRes.body.id)

    const victimResetRes = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'other.victim@te.st', answer: 'x', new: 'pwned', repeat: 'pwned' })
    assert.equal(victimResetRes.status, 401)

    const ownResetRes = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'attacker@te.st', answer: 'x', new: '54321', repeat: '54321' })
    assert.equal(ownResetRes.status, 200)
  })
})

void describe('/api/SecurityAnswers/:id', () => {
  void it('GET existing security answer by id is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .get('/api/SecurityAnswers/1')
      .set(authHeader)

    assert.equal(res.status, 401)
  })

  void it('POST new user with security question and answer stores the answer for that user', async () => {
    const userRes = await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'new.user@te.st',
        password: '12345',
        passwordRepeat: '12345',
        securityQuestion: { id: 1, question: 'Your eldest siblings middle name?' },
        securityAnswer: 'Horst'
      })
    assert.equal(userRes.status, 201)

    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'new.user@te.st', answer: 'Horst', new: '54321', repeat: '54321' })
    assert.equal(res.status, 200)
  })

  void it('POST new user with unknown security question is rejected and no user is created', async () => {
    const user = { email: 'invalid.question@te.st', password: '12345', passwordRepeat: '12345', securityAnswer: 'Horst' }
    const res = await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({ ...user, securityQuestion: { id: 9999 } })
    assert.equal(res.status, 400)

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
