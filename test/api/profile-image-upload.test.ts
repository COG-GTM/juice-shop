/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import path from 'node:path'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/profile/image/file', () => {
  void it('POST profile image file valid for JPG format', async () => {
    const file = path.resolve(__dirname, '../files/validProfileImage.jpg')

    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .post('/profile/image/file')
      .set('Cookie', `token=${token}`)
      .attach('file', file)
      .redirects(0)

    assert.equal(res.status, 302)
  })

  void it('POST profile image file invalid type', async () => {
    const file = path.resolve(__dirname, '../files/invalidProfileImageType.docx')

    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .post('/profile/image/file')
      .set('Cookie', `token=${token}`)
      .attach('file', file)

    assert.equal(res.status, 415)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes(`${config.get<string>('application.name')} (Express`))
    assert.ok(res.text.includes('Error: Profile image upload does not accept this file type'))
  })

  void it('POST profile image file forbidden for anonymous user', async () => {
    const file = path.resolve(__dirname, '../files/validProfileImage.jpg')

    const res = await request(app)
      .post('/profile/image/file')
      .attach('file', file)

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })
})

void describe('/profile/image/url', () => {
  async function postImageUrl (imageUrl: string) {
    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    return await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .type('form')
      .send({ imageUrl })
      .redirects(0)
  }

  for (const imageUrl of [
    'cataas.com/cat',
    'http://cataas.com/cat',
    'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
    'https://127.0.0.1/rest/admin/application-version',
    'https://169.254.169.254/latest/meta-data/',
    'https://[::1]/',
    'https://[::ffff:127.0.0.1]/',
    'https://10.0.0.5/_cat/indices',
    'https://localhost:3000/solve/challenges/server-side?key=tRy_H4rd3r_n0thIng_iS_Imp0ssibl3',
    `https://example.com/${'a'.repeat(2048)}`
  ]) {
    void it(`POST profile image URL rejects ${imageUrl.substring(0, 60)}`, async () => {
      const res = await postImageUrl(imageUrl)

      assert.equal(res.status, 400)
      assert.ok(res.text.includes('Image URL must be a public https:// address'))
    })
  }

  void it('POST profile image URL rejects hostnames resolving to loopback addresses', async () => {
    const res = await postImageUrl('https://localhost/image.png')

    assert.equal(res.status, 422)
    assert.ok(res.text.includes('Could not retrieve a valid image from the given URL'))
  })

  void it('POST profile image URL does not store an invalid image URL in the profile page CSP', async () => {
    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })
    const imageUrl = "https://notanimage.invalid/x.png; script-src 'self' 'unsafe-inline'"

    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .type('form')
      .send({ imageUrl })
      .redirects(0)
    assert.equal(res.status, 422)

    const profile = await request(app)
      .get('/profile')
      .set('Cookie', `token=${token}`)
    assert.equal(profile.headers['content-security-policy'], "img-src 'self'; script-src 'self' 'unsafe-eval'")
  })

  void it('POST profile image URL forbidden for anonymous user before any URL processing', async () => {
    const started = Date.now()
    const res = await request(app)
      .post('/profile/image/url')
      .type('form')
      .send({ imageUrl: 'a'.repeat(100000) })

    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
    assert.ok(Date.now() - started < 2000)
  })

  void it('POST valid image with tampered content length', { skip: 'Fails on CI/CD pipeline' }, async () => {
    const file = path.resolve(__dirname, '../files/validProfileImage.jpg')

    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .post('/profile/image/file')
      .set('Cookie', `token=${token}`)
      .set('Content-Length', '42')
      .attach('file', file)
      .redirects(0)

    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Unexpected end of form'))
  })
})
