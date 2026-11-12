/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/promotion', () => {
  void it('GET promotion video page is publicly accessible', async () => {
    const res = await request(app)
      .get('/promotion')
    assert.equal(res.status, 200)
  })

  void it('GET promotion video page contains embedded video', async () => {
    const res = await request(app)
      .get('/promotion')
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<source src="./video" type="video/mp4">'))
  })

  void it('GET promotion video page contains subtitles as JSON <script>', async () => {
    const res = await request(app)
      .get('/promotion')
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<script id="subtitle" type="application/json" data-label="English" data-lang="en">'))
  })

  void it('GET promotion video page does not let subtitle content break out of its <script>', async (t) => {
    const subtitles = 'WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nHello\n</script><script>alert(`xss`)</script>'
    const readFileSync = fs.readFileSync
    t.mock.method(fs, 'readFileSync', (file: fs.PathOrFileDescriptor, ...args: any[]) =>
      String(file).endsWith('owasp_promo.vtt') ? subtitles : readFileSync(file, ...args))
    const res = await request(app)
      .get('/promotion')
    assert.equal(res.status, 200)
    assert.ok(!res.text.includes('</script><script>alert(`xss`)</script>'))
    const match = res.text.match(/<script id="subtitle"[^>]*>([\s\S]*?)<\/script>/)
    assert.ok(match)
    assert.equal(JSON.parse(match[1]), subtitles)
  })
})

void describe('/video', () => {
  void it('GET promotion video is publicly accessible', async () => {
    const res = await request(app)
      .get('/video')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('video/mp4'))
  })
})
