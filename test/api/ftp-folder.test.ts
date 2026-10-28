/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

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

function responseText (res: request.Response): string {
  return res.text ?? (Buffer.isBuffer(res.body) ? res.body.toString('utf-8') : '')
}

void describe('/ftp', () => {
  void it('GET does not serve a directory listing', async () => {
    const res = await request(app)
      .get('/ftp')
    assert.ok(!responseText(res).includes('listing directory /ftp'))
    assert.ok(!responseText(res).includes('acquisitions.md'))
  })

  void it('GET a non-existing Markdown file in /ftp will return a 404 error', async () => {
    const res = await request(app)
      .get('/ftp/doesnotexist.md')
    assert.equal(res.status, 404)
  })

  void it('GET a non-existing PDF file in /ftp will return a 404 error', async () => {
    const res = await request(app)
      .get('/ftp/doesnotexist.pdf')
    assert.equal(res.status, 404)
  })

  void it('GET a non-existing order confirmation in /ftp will return a 404 error', async () => {
    const res = await request(app)
      .get('/ftp/order_0000-0000000000000000.pdf')
    assert.equal(res.status, 404)
  })

  for (const file of ['acquisitions.md', 'announcement_encrypted.md', 'incident-support.kdbx', 'eastere.gg', 'coupons_2013.md.bak', 'package.json.bak', 'package-lock.json.bak', 'suspicious_errors.yml', 'encrypt.pyc']) {
    void it(`GET the non-public file /ftp/${file} will return a 404 error`, async () => {
      const res = await request(app)
        .get(`/ftp/${file}`)
      assert.equal(res.status, 404)
    })
  }

  for (const file of ['eastere.gg', 'suspicious_errors.yml', 'coupons_2013.md.bak', 'package.json.bak', 'encrypt.pyc']) {
    for (const suffix of ['.md', '.pdf']) {
      void it(`GET /ftp/${file} via Poison Null Byte attack with ${suffix} suffix will return a 404 error`, async () => {
        const res = await request(app)
          .get(`/ftp/${file}%2500${suffix}`)
          .buffer(true)
        assert.equal(res.status, 404)
      })
    }
  }

  void it('GET a restricted file directly from file system path on server by tricking route definitions does not serve it', async () => {
    const res = await request(app)
      .get('/ftp///eastere.gg')
      .buffer(true)
    assert.ok(!responseText(res).includes('Congratulations, you found the easter egg!'))
  })

  void it('GET a restricted file directly from file system path on server by appending URL parameter fails with 404 error', async () => {
    const res = await request(app)
      .get('/ftp/eastere.gg?.md')
    assert.equal(res.status, 404)
  })

  void it('GET a file whose name contains a "/" fails with a 403 error', async () => {
    const res = await request(app)
      .get('/ftp/%2fetc%2fos-release%2500.md')
    assert.equal(res.status, 403)
    assert.ok(res.text.includes('Error: File names cannot contain forward slashes!'))
  })

  void it('GET an accessible file directly from file system path on server', async () => {
    const res = await request(app)
      .get('/ftp/legal.md')
    assert.equal(res.status, 200)
    assert.ok(res.text.includes('# Legal Information'))
  })

  void it('GET a non-existing file via direct server file path /ftp will return a 404 error', async () => {
    const res = await request(app)
      .get('/ftp/doesnotexist.md')
    assert.equal(res.status, 404)
  })

  void it('GET file /ftp/quarantine/juicy_malware_linux_amd_64.url', async () => {
    const res = await request(app)
      .get('/ftp/quarantine/juicy_malware_linux_amd_64.url')
    assert.equal(res.status, 200)
  })

  void it('GET file /ftp/quarantine/juicy_malware_linux_arm_64.url', async () => {
    const res = await request(app)
      .get('/ftp/quarantine/juicy_malware_linux_arm_64.url')
    assert.equal(res.status, 200)
  })

  void it('GET existing file /ftp/quarantine/juicy_malware_macos_64.url', async () => {
    const res = await request(app)
      .get('/ftp/quarantine/juicy_malware_macos_64.url')
    assert.equal(res.status, 200)
  })

  void it('GET existing file /ftp/quarantine/juicy_malware_windows_64.exe.url', async () => {
    const res = await request(app)
      .get('/ftp/quarantine/juicy_malware_windows_64.exe.url')
    assert.equal(res.status, 200)
  })
})
