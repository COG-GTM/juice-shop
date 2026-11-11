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
import type { Product as ProductConfig } from '../../lib/config.types'
import { challenges } from '../../data/datacache'
import * as security from '../../lib/insecurity'
import * as utils from '../../lib/utils'
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'

const tamperingProductId = config.get<ProductConfig[]>('products').findIndex((product) => !!product.urlForProductTamperingChallenge) + 1

let app: Express
const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' }
const jsonHeader = { 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/api/Products', () => {
  void it('GET all products', async () => {
    const res = await request(app)
      .get('/api/Products')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.ok(Array.isArray(res.body.data))
    for (const product of res.body.data) {
      assert.equal(typeof product.id, 'number')
      assert.equal(typeof product.name, 'string')
      assert.equal(typeof product.description, 'string')
      assert.equal(typeof product.price, 'number')
      assert.equal(typeof product.deluxePrice, 'number')
      assert.equal(typeof product.image, 'string')
    }
  })

  void it('POST new product is forbidden via public API', async () => {
    const res = await request(app)
      .post('/api/Products')
      .send({
        name: 'Dirt Juice (1000ml)',
        description: 'Made from ugly dirt.',
        price: 0.99,
        image: 'dirt_juice.jpg'
      })
    assert.equal(res.status, 401)
  })

  if (utils.isChallengeEnabled(challenges.restfulXssChallenge)) {
    void it('POST new product does not filter XSS attacks', async () => {
      const res = await request(app)
        .post('/api/Products')
        .set(authHeader)
        .send({
          name: 'XSS Juice (42ml)',
          description: '<iframe src="javascript:alert(`xss`)">',
          price: 9999.99,
          image: 'xss3juice.jpg'
        })
      assert.ok(res.headers['content-type']?.includes('application/json'))
      assert.equal(res.body.data.description, '<iframe src="javascript:alert(`xss`)">')
    })
  }
})

void describe('/api/Products/:id', () => {
  void it('GET existing product by id', async () => {
    const res = await request(app)
      .get('/api/Products/1')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.data.id, 'number')
    assert.equal(typeof res.body.data.name, 'string')
    assert.equal(typeof res.body.data.description, 'string')
    assert.equal(typeof res.body.data.price, 'number')
    assert.equal(typeof res.body.data.deluxePrice, 'number')
    assert.equal(typeof res.body.data.image, 'string')
    assert.equal(typeof res.body.data.createdAt, 'string')
    assert.equal(typeof res.body.data.updatedAt, 'string')
    assert.equal(res.body.data.id, 1)
  })

  void it('GET non-existing product by id', async () => {
    const res = await request(app)
      .get('/api/Products/4711')
    assert.equal(res.status, 404)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.message, 'Not Found')
  })

  void it('PUT update existing product is possible due to Missing Function-Level Access Control vulnerability', async () => {
    const res = await request(app)
      .put('/api/Products/' + tamperingProductId)
      .set(jsonHeader)
      .send({
        description: '<a href="http://kimminich.de" target="_blank">More...</a>'
      })
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.description, '<a href="http://kimminich.de" target="_blank">More...</a>')
  })

  void it('GET product with unknown description does not write it into locale files', async () => {
    const original = await request(app).get('/api/Products/1')
    const description = 'i18n-write-probe-' + crypto.randomUUID()
    await request(app).put('/api/Products/1').set(jsonHeader).send({ description })
    try {
      for (const language of ['en', 'de_DE']) {
        await request(app).get('/api/Products').set('Cookie', `language=${language}`)
        await request(app).get('/api/Products/1').set('Cookie', `language=${language}`)
        const localeFile = fs.readFileSync(path.resolve('i18n', `${language}.json`), 'utf8')
        assert.ok(!localeFile.includes(description))
      }
    } finally {
      await request(app).put('/api/Products/1').set(jsonHeader).send({ description: original.body.data.description })
    }
  })

  void it('DELETE existing product is forbidden via public API', async () => {
    const res = await request(app)
      .delete('/api/Products/1')
    assert.equal(res.status, 401)
  })

  void it('DELETE existing product is forbidden via API even when authenticated', async () => {
    const res = await request(app)
      .delete('/api/Products/1')
      .set(authHeader)
    assert.equal(res.status, 401)
  })
})
