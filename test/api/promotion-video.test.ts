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

  void it('GET promotion video page contains subtitles as <script>', async () => {
    const res = await request(app)
      .get('/promotion')
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<script id="subtitle" type="text/vtt" data-label="English" data-lang="en">'))
  })

  void it('GET promotion video page escapes markup in subtitles', async () => {
    const subtitlesFile = 'frontend/dist/frontend/assets/public/videos/owasp_promo.vtt'
    const original = fs.readFileSync(subtitlesFile)
    fs.writeFileSync(subtitlesFile, 'WEBVTT\n\n</script><script>alert(`xss`)</script>\n')
    try {
      const res = await request(app)
        .get('/promotion')
      assert.equal(res.status, 200)
      assert.ok(!res.text.includes('<script>alert(`xss`)</script>'))
      assert.ok(res.text.includes('\\u003c/script>\\u003cscript>alert(`xss`)\\u003c/script>'))
    } finally {
      fs.writeFileSync(subtitlesFile, original)
    }
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
