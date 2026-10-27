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
let authHeader: { Cookie: string }

before(async () => {
  const result = await createTestApp()
  app = result.app
  const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
  authHeader = { Cookie: `token=${token}` }
}, { timeout: 60000 })

void describe('/profile', () => {
  void it('GET user profile is forbidden for unauthenticated user', async () => {
    const res = await request(app)
      .get('/profile')

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes(`<h1>${config.get<string>('application.name')} (Express`))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('GET user profile of authenticated user', async () => {
    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('id="email" type="email" name="email" value="jim@juice-sh.op"'))
  })

  void it('POST update username of authenticated user', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .field('username', 'Localhorst')
      .redirects(0)

    assert.equal(res.status, 302)
  })

  for (const [name, headers] of [
    ['cross-site Sec-Fetch-Site', { 'Sec-Fetch-Site': 'cross-site' }],
    ['foreign Origin', { Origin: 'http://htmledit.squarefree.com' }],
    ['foreign Referer', { Referer: 'https://attacker.example/csrf.html' }],
    ['opaque Origin', { Origin: 'null' }],
    ['same hostname on another port', { Origin: 'http://localhost:8080' }]
  ] as Array<[string, Record<string, string>]>) {
    void it(`POST update username with ${name} is rejected`, async () => {
      const res = await request(app)
        .post('/profile')
        .set('Cookie', authHeader.Cookie)
        .set('Host', 'localhost:3000')
        .set(headers)
        .type('form')
        .send('username=CSRF')
        .redirects(0)

      assert.equal(res.status, 403)
      assert.ok(res.text.includes('Error: Cross-site profile update rejected'))
      const profile = await request(app).get('/profile').set(authHeader)
      assert.ok(!profile.text.includes('value="CSRF"'))
    })
  }

  void it('POST update username from same origin sets a SameSite=Lax token cookie', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .set('Host', 'localhost:3000')
      .set('Origin', 'http://localhost:3000')
      .set('Sec-Fetch-Site', 'same-origin')
      .type('form')
      .send('username=Localhorst')
      .redirects(0)

    assert.equal(res.status, 302)
    const cookies = [res.headers['set-cookie'] ?? []].flat()
    assert.ok(cookies.some((c: string) => c.startsWith('token=') && c.includes('SameSite=Lax')))
  })
})
