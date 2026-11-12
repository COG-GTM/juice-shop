/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import path from 'node:path'
import fs from 'node:fs'
import http from 'node:http'
import { type AddressInfo } from 'node:net'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import { UserModel } from '../../models/user'

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
  void it('POST profile image URL valid for image available online', async () => {
    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', 'cataas.com/cat')
      .redirects(0)

    assert.equal(res.status, 302)
  })

  void it('POST profile image URL redirects even for invalid image URL', async () => {
    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', 'https://notanimage.here/100/100')
      .redirects(0)

    assert.equal(res.status, 302)
  })

  for (const imageUrl of ['http://127.0.0.1:3000/', 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', 'https://127.0.0.1:3000/rest/admin/application-configuration', "https://a.png; script-src 'unsafe-inline' 'self' 'unsafe-eval'"]) {
    void it(`POST profile image URL ${imageUrl} is neither fetched nor stored as profile image`, async () => {
      const { token } = await login(app, {
        email: `jim@${config.get<string>('application.domain')}`,
        password: 'ncc-1701'
      })
      const before = await UserModel.findOne({ where: { email: `jim@${config.get<string>('application.domain')}` } })

      const res = await request(app)
        .post('/profile/image/url')
        .set('Cookie', `token=${token}`)
        .field('imageUrl', imageUrl)
        .redirects(0)

      assert.equal(res.status, 302)
      const after = await UserModel.findByPk(before?.id)
      assert.equal(after?.profileImage, before?.profileImage)
      assert.ok(!after?.profileImage.includes(imageUrl))
    })
  }

  void describe('internal image server', () => {
    const hits: string[] = []
    let server: http.Server
    let port: number

    before(async () => {
      const image = fs.readFileSync(path.resolve(__dirname, '../files/validProfileImage.jpg'))
      server = http.createServer((req, res) => {
        hits.push(req.url ?? '')
        res.writeHead(200, { 'Content-Type': 'image/jpeg' })
        res.end(image)
      })
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
      port = (server.address() as AddressInfo).port
    })

    after(async () => { await new Promise((resolve) => server.close(resolve)) })

    for (const host of ['127.0.0.1', 'localhost', '[::ffff:127.0.0.1]']) {
      void it(`POST profile image URL on internal host ${host} never reaches the server`, async () => {
        const { token } = await login(app, {
          email: `jim@${config.get<string>('application.domain')}`,
          password: 'ncc-1701'
        })
        const before = await UserModel.findOne({ where: { email: `jim@${config.get<string>('application.domain')}` } })

        for (const protocol of ['http', 'https']) {
          const res = await request(app)
            .post('/profile/image/url')
            .set('Cookie', `token=${token}`)
            .field('imageUrl', `${protocol}://${host}:${port}/latest/meta-data/image.jpg`)
            .redirects(0)
          assert.equal(res.status, 302)
        }

        assert.deepEqual(hits, [])
        const after = await UserModel.findByPk(before?.id)
        assert.equal(after?.profileImage, before?.profileImage)
      })
    }
  })

  void it('POST profile image URL forbidden for anonymous user', { skip: 'FIXME runs into "socket hang up"' }, async () => {
    const res = await request(app)
      .post('/profile/image/url')
      .field('imageUrl', 'cataas.com/cat')

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
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
