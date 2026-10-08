/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import fs from 'node:fs'
import path from 'node:path'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import * as security from '../../lib/insecurity'
import { MEMORY_IMAGE_MAX_BYTES } from '../../lib/memoryImageUpload'

let app: Express

const uploadsDir = path.resolve('frontend/dist/frontend/assets/public/images/uploads/')
const uploadedFiles = () => fs.existsSync(uploadsDir) ? fs.readdirSync(uploadsDir) : []

async function jimToken () {
  const { token } = await login(app, {
    email: 'jim@' + config.get<string>('application.domain'),
    password: 'ncc-1701'
  })
  return token
}

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/memories', () => {
  void it('GET memories via public API', async () => {
    const res = await request(app)
      .get('/rest/memories')
    assert.equal(res.status, 200)
  })

  void it('GET memories via a valid authorization token', async () => {
    const { token } = await login(app, {
      email: 'jim@' + config.get<string>('application.domain'),
      password: 'ncc-1701'
    })
    const res = await request(app)
      .get('/rest/memories')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
    assert.equal(res.status, 200)
  })

  void it('POST new memory is forbidden via public API', async () => {
    const file = path.resolve(__dirname, '../files/validProfileImage.jpg')
    const res = await request(app)
      .post('/rest/memories')
      .attach('image', file, 'Valid Image')
      .field('caption', 'Valid Image')
    assert.equal(res.status, 401)
  })

  void it('POST new memory via public API does not write the image to disk', async () => {
    const before = uploadedFiles()
    const res = await request(app)
      .post('/rest/memories')
      .attach('image', Buffer.alloc(150000), { filename: 'anonymous-upload.png', contentType: 'image/png' })
      .field('caption', 'Anonymous Upload')
    assert.equal(res.status, 401)
    assert.deepEqual(uploadedFiles(), before)
  })

  void it('POST new memory with a token that is not bound to a logged-in user does not write the image to disk', async () => {
    const before = uploadedFiles()
    const res = await request(app)
      .post('/rest/memories')
      .set('Authorization', 'Bearer ' + security.authorize({ data: { id: 2, email: 'jim@' + config.get<string>('application.domain') } }))
      .attach('image', Buffer.alloc(150000), { filename: 'unbound-token.png', contentType: 'image/png' })
      .field('caption', 'Unbound Token')
    assert.equal(res.status, 401)
    assert.deepEqual(uploadedFiles(), before)
  })

  void it('POST new memory image file exceeding the size limit is rejected and not kept on disk', async () => {
    const token = await jimToken()
    const before = uploadedFiles()
    const res = await request(app)
      .post('/rest/memories')
      .set('Authorization', 'Bearer ' + token)
      .attach('image', Buffer.alloc(MEMORY_IMAGE_MAX_BYTES + 1), { filename: 'too-large.png', contentType: 'image/png' })
      .field('caption', 'Too Large Image')
    assert.equal(res.status, 413)
    assert.deepEqual(uploadedFiles(), before)
  })

  void it('POST new memory with more than one image file is rejected', async () => {
    const token = await jimToken()
    const file = path.resolve(__dirname, '../files/validProfileImage.jpg')
    const res = await request(app)
      .post('/rest/memories')
      .set('Authorization', 'Bearer ' + token)
      .attach('image', file, 'Valid Image')
      .attach('image', file, 'Valid Image')
      .field('caption', 'Two Images')
    assert.equal(res.status, 400)
  })

  void it('POST new memory image file invalid type', async () => {
    const file = path.resolve(__dirname, '../files/invalidProfileImageType.docx')
    const { token } = await login(app, {
      email: 'jim@' + config.get<string>('application.domain'),
      password: 'ncc-1701'
    })
    const res = await request(app)
      .post('/rest/memories')
      .set('Authorization', 'Bearer ' + token)
      .attach('image', file, 'Valid Image')
      .field('caption', 'Valid Image')
    assert.equal(res.status, 500)
  })

  void it('POST new memory image file is not passed - 1', async () => {
    const { token } = await login(app, {
      email: 'jim@' + config.get<string>('application.domain'),
      password: 'ncc-1701'
    })
    const res = await request(app)
      .post('/rest/memories')
      .set('Authorization', 'Bearer ' + token)
    assert.equal(res.status, 400)
    assert.equal(res.body.error, 'File is not passed')
  })

  void it('POST new memory image file is not passed - 2', async () => {
    const { token } = await login(app, {
      email: 'jim@' + config.get<string>('application.domain'),
      password: 'ncc-1701'
    })
    const res = await request(app)
      .post('/rest/memories')
      .set('Authorization', 'Bearer ' + token)
      .field('key1', 'value1')
      .field('key2', 'value2')
    assert.equal(res.status, 400)
    assert.equal(res.body.error, 'File is not passed')
  })

  void it('POST new memory with valid for JPG format image', async () => {
    const file = path.resolve(__dirname, '../files/validProfileImage.jpg')
    const { token } = await login(app, {
      email: 'jim@' + config.get<string>('application.domain'),
      password: 'ncc-1701'
    })
    const res = await request(app)
      .post('/rest/memories')
      .set('Authorization', 'Bearer ' + token)
      .attach('image', file, 'Valid Image')
      .field('caption', 'Valid Image')
    assert.equal(res.status, 200)
    assert.equal(res.body.data.caption, 'Valid Image')
    assert.equal(res.body.data.UserId, 2)
  })

  void it('Should not crash the node-js server when sending invalid content like described in CVE-2022-24434', async () => {
    const token = await jimToken()
    const res = await request(app)
      .post('/rest/memories')
      .set('Authorization', 'Bearer ' + token)
      .set('Content-Type', 'multipart/form-data; boundary=----WebKitFormBoundaryoo6vortfDzBsDiro')
      .send('------WebKitFormBoundaryoo6vortfDzBsDiro\r\n Content-Disposition: form-data; name="bildbeschreibung"\r\n\r\n\r\n------WebKitFormBoundaryoo6vortfDzBsDiro--')
    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Error: Malformed part header'))
  })
})
