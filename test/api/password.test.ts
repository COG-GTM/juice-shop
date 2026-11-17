/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import { PasswordResetTokenModel } from '../../models/passwordResetToken'
import { UserModel } from '../../models/user'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

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

const hashToken = (token: string) => crypto.createHash('sha256').update(token).digest('hex')

async function createResetToken (email: string, expiresAt = new Date(Date.now() + 60000)) {
  const user = await UserModel.findOne({ where: { email } })
  assert.ok(user)
  const token = crypto.randomBytes(32).toString('base64url')
  await PasswordResetTokenModel.create({ UserId: user.id, tokenHash: hashToken(token), expiresAt })
  return token
}

void describe('/rest/user/reset-password/request', () => {
  void it('POST reset request for existing user stores a hashed one-time token and returns a generic response', async () => {
    const email = 'jim@' + config.get<string>('application.domain')
    const res = await request(app)
      .post('/rest/user/reset-password/request')
      .set({ 'content-type': 'application/json' })
      .send({ email })

    assert.equal(res.status, 200)
    assert.deepEqual(res.body, { status: 'success' })
    const user = await UserModel.findOne({ where: { email } })
    const tokens = await PasswordResetTokenModel.findAll({ where: { UserId: user?.id } })
    assert.equal(tokens.length, 1)
    assert.match(tokens[0].tokenHash, /^[0-9a-f]{64}$/)
    assert.ok(tokens[0].expiresAt.getTime() > Date.now())
  })

  void it('POST reset request for unknown email returns the same generic response', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password/request')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'nobody@' + config.get<string>('application.domain') })

    assert.equal(res.status, 200)
    assert.deepEqual(res.body, { status: 'success' })
  })

  void it('POST reset request without email throws a 400 error', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password/request')
      .set({ 'content-type': 'application/json' })
      .send({})

    assert.equal(res.status, 400)
    assert.ok(res.text.includes('Email address cannot be empty.'))
  })
})

void describe('/rest/user/reset-password', () => {
  void it('POST password reset with valid one-time token succeeds without leaking the password hash', async () => {
    const email = 'bender@' + config.get<string>('application.domain')
    const token = await createResetToken(email)
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({ token, new: 'Brannigan 8=o Leela', repeat: 'Brannigan 8=o Leela' })

    assert.equal(res.status, 200)
    assert.equal(res.body.user.email, email)
    assert.equal(res.body.user.password, undefined)

    const loginRes = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({ email, password: 'Brannigan 8=o Leela' })
    assert.equal(loginRes.status, 200)
  })

  void it('POST password reset with an already used token is rejected', async () => {
    const token = await createResetToken('bjoern@' + config.get<string>('application.domain'))
    const first = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({ token, new: 'abcdef', repeat: 'abcdef' })
    assert.equal(first.status, 200)

    const second = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({ token, new: 'ghijkl', repeat: 'ghijkl' })
    assert.equal(second.status, 401)
    assert.ok(second.text.includes('Invalid or expired password reset link.'))
  })

  void it('POST password reset with an expired token is rejected', async () => {
    const token = await createResetToken('morty@' + config.get<string>('application.domain'), new Date(Date.now() - 1000))
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({ token, new: 'abcdef', repeat: 'abcdef' })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Invalid or expired password reset link.'))
  })

  void it('POST password reset with email and correct security answer but no token is blocked', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'jim@' + config.get<string>('application.domain'),
        answer: 'Samuel',
        new: 'ncc-1701',
        repeat: 'ncc-1701'
      })

    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('POST password reset with unknown token is rejected', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({ token: 'not-a-real-token', new: 'abcdef', repeat: 'abcdef' })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Invalid or expired password reset link.'))
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
      .send({ token: 'some-token', repeat: '12345' })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Password cannot be empty.'))
  })

  void it('POST password reset with mismatching passwords throws a 401 error', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({ token: 'some-token', new: '12345', repeat: '1234_' })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('New and repeated password do not match.'))
  })
})

void describe('reset-password rate limiting', () => {
  void it('does not let client-supplied X-Forwarded-For entries in front of the trusted proxy bypass the limit', async () => {
    let lastStatus = 0
    for (let i = 0; i < 101; i++) {
      const res = await request(app)
        .post('/rest/user/reset-password')
        .set({ 'content-type': 'application/json', 'X-Forwarded-For': `10.0.${Math.floor(i / 250)}.${i % 250}, 203.0.113.7` })
        .send({ token: 'invalid', new: 'abcdef', repeat: 'abcdef' })
      lastStatus = res.status
    }
    assert.equal(lastStatus, 429)
  })
})
