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
import { login, register } from './helpers/auth'

let app: Express
const authHeader = { Authorization: `Bearer ${security.authorize()}`, 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

async function registerUser (email: string) {
  await register(app, { email, password: '12345' })
  const { token } = await login(app, { email, password: '12345' })
  const user = security.authenticatedUsers.get(token)
  assert.ok(user)
  return user.data
}

async function resetPassword (email: string, answer: string) {
  return await request(app)
    .post('/rest/user/reset-password')
    .set({ 'content-type': 'application/json' })
    .send({ email, answer, new: 'newPassword', repeat: 'newPassword' })
}

void describe('/api/SecurityAnswers', () => {
  void it('GET all security answers is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .get('/api/SecurityAnswers')
      .set(authHeader)

    assert.equal(res.status, 401)
  })

  void it('POST security answer is forbidden when not authenticated', async () => {
    const victim = await registerUser('unauth.victim@te.st')

    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set({ 'content-type': 'application/json' })
      .send({
        UserId: victim.id,
        SecurityQuestionId: 1,
        answer: 'Mallory'
      })

    assert.equal(res.status, 401)

    const resetRes = await resetPassword('unauth.victim@te.st', 'Mallory')
    assert.equal(resetRes.status, 401)
  })

  void it('POST security answer for another user is stored for the authenticated user instead', async () => {
    const victim = await registerUser('idor.victim@te.st')
    const attacker = await registerUser('idor.attacker@te.st')
    const { token } = await login(app, { email: 'idor.attacker@te.st', password: '12345' })

    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })
      .send({
        UserId: victim.id,
        SecurityQuestionId: 1,
        answer: 'Mallory'
      })

    assert.equal(res.status, 201)
    assert.equal(res.body.data.UserId, attacker.id)

    const resetRes = await resetPassword('idor.victim@te.st', 'Mallory')
    assert.equal(resetRes.status, 401)
  })

  void it('POST new security answer for user who already has one fails from unique constraint', async () => {
    const userRes = await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'answered.user@te.st',
        password: '12345',
        passwordRepeat: '12345',
        securityQuestion: { id: 1 },
        securityAnswer: 'Horst'
      })
    assert.equal(userRes.status, 201)
    const { token } = await login(app, { email: 'answered.user@te.st', password: '12345' })

    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set({ Authorization: `Bearer ${token}`, 'content-type': 'application/json' })
      .send({
        SecurityQuestionId: 1,
        answer: 'Blurp'
      })

    assert.equal(res.status, 400)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.message, 'Validation error')
  })

  void it('POST user registration with security question stores the answer for the new user', async () => {
    const userRes = await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'registered.with.answer@te.st',
        password: '12345',
        passwordRepeat: '12345',
        securityQuestion: { id: 1 },
        securityAnswer: 'Horst'
      })
    assert.equal(userRes.status, 201)

    const resetRes = await resetPassword('registered.with.answer@te.st', 'Horst')
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
