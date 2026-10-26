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
import { setPasswordResetMailer } from '../../lib/passwordReset'

let app: Express

const sentResetTokens = new Map<string, string>()

before(async () => {
  const result = await createTestApp()
  app = result.app
  setPasswordResetMailer(async (email, token) => { sentResetTokens.set(email, token) })
}, { timeout: 60000 })

async function requestResetToken (email: string) {
  sentResetTokens.delete(email)
  const res = await request(app)
    .post('/rest/user/reset-password/request')
    .set({ 'content-type': 'application/json' })
    .send({ email })
  assert.equal(res.status, 200)
  return sentResetTokens.get(email)
}

async function resetPassword (body: Record<string, unknown>) {
  return await request(app)
    .post('/rest/user/reset-password')
    .set({ 'content-type': 'application/json' })
    .send(body)
}

void describe('/rest/user/change-password', () => {
  void it('GET password change for newly created user with recognized token as Authorization header', async () => {
    await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'kuni@be.rt',
        password: 'kunigunde'
      })
      .expect(201)

    const { token } = await login(app, { email: 'kuni@be.rt', password: 'kunigunde' })

    const res = await request(app)
      .get('/rest/user/change-password?current=kunigunde&new=foo&repeat=foo')
      .set({ Authorization: 'Bearer ' + token })

    assert.equal(res.status, 200)
  })

  void it('GET password change with passing wrong current password', async () => {
    const { token } = await login(app, {
      email: 'bjoern@' + config.get<string>('application.domain'),
      password: 'monkey summer birthday are all bad passwords but work just fine in a long passphrase'
    })

    const res = await request(app)
      .get('/rest/user/change-password?current=definetely_wrong&new=blubb&repeat=blubb')
      .set({ Authorization: 'Bearer ' + token })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Current password is not correct'))
  })

  void it('GET password change without passing any passwords', async () => {
    const res = await request(app)
      .get('/rest/user/change-password')

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Password cannot be empty'))
  })

  void it('GET password change with passing wrong repeated password', async () => {
    const res = await request(app)
      .get('/rest/user/change-password?new=foo&repeat=bar')

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('New and repeated password do not match'))
  })

  void it('GET password change without passing an authorization token', async () => {
    const res = await request(app)
      .get('/rest/user/change-password?new=foo&repeat=foo')

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<h1>' + config.get<string>('application.name') + ' (Express'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('GET password change with passing unrecognized authorization token', async () => {
    const res = await request(app)
      .get('/rest/user/change-password?new=foo&repeat=foo')
      .set({ Authorization: 'Bearer unknown' })

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<h1>' + config.get<string>('application.name') + ' (Express'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('GET password change for Bender without current password using GET request', async () => {
    const { token } = await login(app, {
      email: 'bender@' + config.get<string>('application.domain'),
      password: 'OhG0dPlease1nsertLiquor!'
    })

    const res = await request(app)
      .get('/rest/user/change-password?new=slurmCl4ssic&repeat=slurmCl4ssic')
      .set({ Authorization: 'Bearer ' + token })

    assert.equal(res.status, 200)
  })
})

void describe('/rest/user/reset-password/request', () => {
  void it('POST reset code request for a known user sends a reset code', async () => {
    const token = await requestResetToken('jim@' + config.get<string>('application.domain'))
    assert.ok(token)
    assert.match(token, /^[0-9a-f]{64}$/)
  })

  void it('POST reset code request for an unknown email address responds identically without sending a code', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password/request')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'nobody@' + config.get<string>('application.domain') })

    assert.equal(res.status, 200)
    assert.deepEqual(res.body, { status: 'success' })
    assert.equal(sentResetTokens.get('nobody@' + config.get<string>('application.domain')), undefined)
  })

  void it('POST reset code request without email address is rejected', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password/request')
      .set({ 'content-type': 'application/json' })
      .send({ email: { $ne: '' } })

    assert.equal(res.status, 400)
  })
})

void describe('/rest/user/reset-password', () => {
  const resets = [
    { name: 'Jim', email: () => 'jim@' + config.get<string>('application.domain'), answer: 'Samuel', password: 'ncc-1701' },
    { name: 'Bender', email: () => 'bender@' + config.get<string>('application.domain'), answer: 'Stop\'n\'Drop', password: 'OhG0dPlease1nsertLiquor!' },
    { name: 'Bjoern\u00b4s internal account', email: () => 'bjoern@' + config.get<string>('application.domain'), answer: 'West-2082', password: 'monkey summer birthday are all bad passwords but work just fine in a long passphrase' },
    { name: 'Bjoern\u00b4s OWASP account', email: () => 'bjoern@owasp.org', answer: 'Zaya', password: 'kitten lesser pooch karate buffoon indoors' },
    { name: 'Morty', email: () => 'morty@' + config.get<string>('application.domain'), answer: '5N0wb41L', password: 'iBurri3dMySe1fInTheB4ckyard!' }
  ]

  for (const { name, email, answer, password } of resets) {
    void it(`POST password reset for ${name} with emailed reset code and correct answer to the security question`, async () => {
      const token = await requestResetToken(email())
      const res = await resetPassword({ email: email(), token, answer, new: password, repeat: password })

      assert.equal(res.status, 200)
    })
  }

  void it('POST password reset with correct answer but without reset code does not change the password', async () => {
    const email = 'jim@' + config.get<string>('application.domain')
    const res = await resetPassword({ email, answer: 'Samuel', new: 'hijacked1', repeat: 'hijacked1' })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Invalid or expired password reset code.'))
    await assert.rejects(login(app, { email, password: 'hijacked1' }))
  })

  void it('POST password reset with correct answer and forged reset code does not change the password', async () => {
    const email = 'jim@' + config.get<string>('application.domain')
    const res = await resetPassword({ email, token: 'a'.repeat(64), answer: 'Samuel', new: 'hijacked1', repeat: 'hijacked1' })

    assert.equal(res.status, 401)
    await assert.rejects(login(app, { email, password: 'hijacked1' }))
  })

  void it('POST password reset with reset code issued for a different account is rejected', async () => {
    const token = await requestResetToken('bender@' + config.get<string>('application.domain'))
    const res = await resetPassword({ email: 'jim@' + config.get<string>('application.domain'), token, answer: 'Samuel', new: 'hijacked1', repeat: 'hijacked1' })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Invalid or expired password reset code.'))
  })

  void it('POST password reset code can only be used once', async () => {
    const email = 'jim@' + config.get<string>('application.domain')
    const token = await requestResetToken(email)
    const first = await resetPassword({ email, token, answer: 'Samuel', new: 'ncc-1701', repeat: 'ncc-1701' })
    assert.equal(first.status, 200)

    const second = await resetPassword({ email, token, answer: 'Samuel', new: 'hijacked1', repeat: 'hijacked1' })
    assert.equal(second.status, 401)
    assert.ok(second.text.includes('Invalid or expired password reset code.'))
  })

  void it('POST password reset invalidates existing sessions of the account', async () => {
    const email = 'bender@' + config.get<string>('application.domain')
    const authentication = await login(app, { email, password: 'OhG0dPlease1nsertLiquor!' })
    const before = await request(app)
      .get('/rest/basket/' + authentication.bid)
      .set({ Authorization: 'Bearer ' + authentication.token })
    assert.equal(before.status, 200)

    const token = await requestResetToken(email)
    const res = await resetPassword({ email, token, answer: 'Stop\'n\'Drop', new: 'OhG0dPlease1nsertLiquor!', repeat: 'OhG0dPlease1nsertLiquor!' })
    assert.equal(res.status, 200)

    const after = await request(app)
      .get('/rest/basket/' + authentication.bid)
      .set({ Authorization: 'Bearer ' + authentication.token })
    assert.equal(after.status, 401)

    const freshAuthentication = await login(app, { email, password: 'OhG0dPlease1nsertLiquor!' })
    const fresh = await request(app)
      .get('/rest/basket/' + freshAuthentication.bid)
      .set({ Authorization: 'Bearer ' + freshAuthentication.token })
    assert.equal(fresh.status, 200)
  })

  void it('POST password reset code is consumed by the first of concurrent resets', async () => {
    const email = 'jim@' + config.get<string>('application.domain')
    const token = await requestResetToken(email)
    const results = await Promise.all([
      resetPassword({ email, token, answer: 'Samuel', new: 'ncc-1701', repeat: 'ncc-1701' }),
      resetPassword({ email, token, answer: 'Samuel', new: 'hijacked1', repeat: 'hijacked1' })
    ])

    assert.deepEqual(results.map(res => res.status).sort(), [200, 401])
  })

  void it('POST password reset with wrong answer to security question', async () => {
    const email = 'bjoern@' + config.get<string>('application.domain')
    const token = await requestResetToken(email)
    const res = await resetPassword({ email, token, answer: '25436', new: '12345', repeat: '12345' })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Wrong answer to security question.'))
  })

  void it('POST password reset locks the account after too many failed attempts', async () => {
    const email = 'morty@' + config.get<string>('application.domain')
    const token = await requestResetToken(email)
    for (let i = 0; i < 5; i++) {
      await resetPassword({ email, token, answer: 'wrong' + i, new: '12345', repeat: '12345' })
    }

    const res = await resetPassword({ email, token, answer: '5N0wb41L', new: 'iBurri3dMySe1fInTheB4ckyard!', repeat: 'iBurri3dMySe1fInTheB4ckyard!' })
    assert.equal(res.status, 429)
    assert.ok(res.text.includes('Too many failed password reset attempts'))
  })

  void it('POST password reset without any data is blocked', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<h1>' + config.get<string>('application.name') + ' (Express'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('POST password reset without new password throws a 401 error', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern@' + config.get<string>('application.domain'),
        answer: 'W-2082',
        repeat: '12345'
      })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Password cannot be empty.'))
  })

  void it('POST password reset with mismatching passwords throws a 401 error', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern@' + config.get<string>('application.domain'),
        answer: 'W-2082',
        new: '12345',
        repeat: '1234_'
      })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('New and repeated password do not match.'))
  })

  void it('POST password reset with no email address throws a 412 error', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        answer: 'W-2082',
        new: 'abcdef',
        repeat: 'abcdef'
      })

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<h1>' + config.get<string>('application.name') + ' (Express'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('POST password reset with no answer to the security question throws a 412 error', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern@' + config.get<string>('application.domain'),
        new: 'abcdef',
        repeat: 'abcdef'
      })

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<h1>' + config.get<string>('application.name') + ' (Express'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('POST password reset with non-string email address is blocked', async () => {
    const res = await resetPassword({ email: { $ne: '' }, answer: 'Samuel', new: 'abcdef', repeat: 'abcdef' })

    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })
})

void describe('/rest/user/reset-password rate limiting', () => {
  void it('POST password reset attempts cannot bypass the rate limit by spoofing X-Forwarded-For', async () => {
    let limited = false
    for (let i = 0; i < 101 && !limited; i++) {
      const res = await request(app)
        .post('/rest/user/reset-password')
        .set({ 'content-type': 'application/json', 'X-Forwarded-For': `10.0.${Math.floor(i / 256)}.${i % 256}` })
        .send({ email: 'support@' + config.get<string>('application.domain'), answer: 'guess' + i, new: '12345', repeat: '12345' })
      limited = res.status === 429 && res.text.includes('Too many requests')
    }

    assert.ok(limited)
  })
})
