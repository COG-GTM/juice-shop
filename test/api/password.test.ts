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

  void it('GET password change for Bender without current password is rejected', async () => {
    const { token } = await login(app, {
      email: 'bender@' + config.get<string>('application.domain'),
      password: 'OhG0dPlease1nsertLiquor!'
    })

    const res = await request(app)
      .get('/rest/user/change-password?new=slurmCl4ssic&repeat=slurmCl4ssic')
      .set({ Authorization: 'Bearer ' + token })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Current password is not correct'))
  })

  void it('GET password change with forged unsigned token registered via whoami is rejected', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')
    const payload = Buffer.from(JSON.stringify({ status: 'success', data: { id: 1, email: 'admin@' + config.get<string>('application.domain') }, iat: 1508639612 })).toString('base64url')
    const forgedToken = header + '.' + payload + '.'

    await request(app)
      .get('/rest/user/whoami')
      .set({ Authorization: 'Bearer ' + forgedToken })

    const res = await request(app)
      .get('/rest/user/change-password?current=whatever&new=pwned123&repeat=pwned123')
      .set({ Authorization: 'Bearer ' + forgedToken })

    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: Blocked illegal activity'))

    await login(app, { email: 'admin@' + config.get<string>('application.domain'), password: 'admin123' })
  })

  void it('GET password change invalidates other sessions of the same user', async () => {
    await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({ email: 'sessions@be.rt', password: 'firstPassw0rd' })
      .expect(201)

    const { token: firstToken } = await login(app, { email: 'sessions@be.rt', password: 'firstPassw0rd' })
    await new Promise(resolve => setTimeout(resolve, 1100))
    const { token: secondToken } = await login(app, { email: 'sessions@be.rt', password: 'firstPassw0rd' })
    assert.notEqual(firstToken, secondToken)

    const res = await request(app)
      .get('/rest/user/change-password?current=firstPassw0rd&new=secondPassw0rd&repeat=secondPassw0rd')
      .set({ Authorization: 'Bearer ' + secondToken })
    assert.equal(res.status, 200)

    const staleRes = await request(app)
      .get('/rest/user/change-password?current=secondPassw0rd&new=thirdPassw0rd&repeat=thirdPassw0rd')
      .set({ Authorization: 'Bearer ' + firstToken })
    assert.equal(staleRes.status, 500)
    assert.ok(staleRes.text.includes('Error: Blocked illegal activity'))
  })
})

void describe('/rest/user/reset-password', () => {
  void it('POST password reset for Jim with correct answer to his security question', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'jim@' + config.get<string>('application.domain'),
        answer: 'Samuel',
        new: 'ncc-1701',
        repeat: 'ncc-1701'
      })

    assert.equal(res.status, 200)
  })

  void it('POST password reset for Bender with correct answer to his security question', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bender@' + config.get<string>('application.domain'),
        answer: 'Stop\'n\'Drop',
        new: 'OhG0dPlease1nsertLiquor!',
        repeat: 'OhG0dPlease1nsertLiquor!'
      })

    assert.equal(res.status, 200)
  })

  void it('POST password reset for Bjoern\u00b4s internal account with correct answer to his security question', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern@' + config.get<string>('application.domain'),
        answer: 'West-2082',
        new: 'monkey summer birthday are all bad passwords but work just fine in a long passphrase',
        repeat: 'monkey summer birthday are all bad passwords but work just fine in a long passphrase'
      })

    assert.equal(res.status, 200)
  })

  void it('POST password reset for Bjoern\u00b4s OWASP account with correct answer to his security question', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern@owasp.org',
        answer: 'Zaya',
        new: 'kitten lesser pooch karate buffoon indoors',
        repeat: 'kitten lesser pooch karate buffoon indoors'
      })

    assert.equal(res.status, 200)
  })

  void it('POST password reset for Morty with correct answer to his security question', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'morty@' + config.get<string>('application.domain'),
        answer: '5N0wb41L',
        new: 'iBurri3dMySe1fInTheB4ckyard!',
        repeat: 'iBurri3dMySe1fInTheB4ckyard!'
      })

    assert.equal(res.status, 200)
  })

  void it('POST password reset with wrong answer to security question', async () => {
    const res = await request(app)
      .post('/rest/user/reset-password')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'bjoern@' + config.get<string>('application.domain'),
        answer: '25436',
        new: '12345',
        repeat: '12345'
      })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Wrong answer to security question.'))
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
})
