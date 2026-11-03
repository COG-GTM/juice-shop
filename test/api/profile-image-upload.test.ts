/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import http from 'node:http'
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
  async function withImageServer (imagePath: string, body: Buffer | string, contentType: string, test: (imageUrl: string) => Promise<void>) {
    const imageServer = http.createServer((req, res) => {
      if (req.url === imagePath) {
        res.writeHead(200, { 'Content-Type': contentType })
        res.end(body)
      } else {
        res.writeHead(404)
        res.end()
      }
    })
    await new Promise<void>((resolve, reject) => {
      imageServer.once('error', reject)
      imageServer.listen(0, '127.0.0.1', resolve)
    })
    const address = imageServer.address()
    if (address === null || typeof address === 'string') {
      throw new Error('Unable to determine local image server port')
    }
    try {
      await test(`http://127.0.0.1:${address.port}${imagePath}`)
    } finally {
      await new Promise<void>((resolve, reject) => {
        imageServer.close((error) => {
          if (error) {
            reject(error)
          } else {
            resolve()
          }
        })
      })
    }
  }

  async function loginAsJim () {
    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })
    const res = await request(app)
      .get('/rest/user/whoami')
      .set('Cookie', `token=${token}`)
    return { token, userId: res.body.user.id as number }
  }

  void it('POST profile image URL rejects SVG content without writing a file', async () => {
    const { token, userId } = await loginAsJim()
    const svgFile = path.resolve(`frontend/dist/frontend/assets/public/images/uploads/${userId}.svg`)
    await fs.rm(svgFile, { force: true })

    await withImageServer('/evil.svg', '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><script>alert(document.cookie)</script></svg>', 'image/svg+xml', async (imageUrl) => {
      const res = await request(app)
        .post('/profile/image/url')
        .set('Cookie', `token=${token}`)
        .field('imageUrl', imageUrl)
        .redirects(0)

      assert.equal(res.status, 415)
      await assert.rejects(fs.access(svgFile))
    })
  })

  void it('POST profile image URL detects raster type instead of URL extension', async () => {
    const { token, userId } = await loginAsJim()
    const jpgBytes = await fs.readFile(path.resolve(__dirname, '../files/validProfileImage.jpg'))
    const jpgFile = path.resolve(`frontend/dist/frontend/assets/public/images/uploads/${userId}.jpg`)
    const svgFile = path.resolve(`frontend/dist/frontend/assets/public/images/uploads/${userId}.svg`)
    await fs.rm(jpgFile, { force: true })
    await fs.rm(svgFile, { force: true })

    await withImageServer('/disguised.svg', jpgBytes, 'image/svg+xml', async (imageUrl) => {
      const res = await request(app)
        .post('/profile/image/url')
        .set('Cookie', `token=${token}`)
        .field('imageUrl', imageUrl)
        .redirects(0)

      assert.equal(res.status, 302)
      assert.deepEqual(await fs.readFile(jpgFile), jpgBytes)
      await assert.rejects(fs.access(svgFile))
    })
  })

  void it('GET profile image upload sets a restrictive content security policy', async () => {
    const { userId } = await loginAsJim()
    const res = await request(app)
      .get(`/assets/public/images/uploads/${userId}.jpg`)

    assert.equal(res.headers['content-security-policy'], "sandbox; default-src 'none'")
  })

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
