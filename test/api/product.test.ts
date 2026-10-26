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
import type { Product as ProductConfig } from '../../lib/config.types'
import * as security from '../../lib/insecurity'

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

  void it('POST new product sanitizes XSS attacks in description', async () => {
    const res = await request(app)
      .post('/api/Products')
      .set(authHeader)
      .send({
        name: 'XSS Juice (42ml)',
        description: 'Tasty<iframe src="javascript:alert(`xss`)"></iframe> juice',
        price: 9999.99,
        image: 'xss3juice.jpg'
      })
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.ok(!res.body.data.description.includes('<iframe'))
    assert.ok(res.body.data.description.includes('Tasty'))
  })
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

  void it('PUT update existing product is forbidden via public API', async () => {
    const original = (await request(app).get('/api/Products/1')).body.data
    const res = await request(app)
      .put('/api/Products/1')
      .set(jsonHeader)
      .send({
        description: '<iframe src="javascript:alert(`xss`)">',
        price: 0.01
      })
    assert.equal(res.status, 401)
    const product = (await request(app).get('/api/Products/1')).body.data
    assert.equal(product.description, original.description)
    assert.equal(product.price, original.price)
  })

  void it('PUT update existing product is forbidden for customers', async () => {
    const res = await request(app)
      .put('/api/Products/' + tamperingProductId)
      .set(authHeader)
      .send({
        description: '<a href="http://kimminich.de" target="_blank">More...</a>'
      })
    assert.equal(res.status, 403)
  })

  void it('PUT update existing product is allowed for accounting users and sanitizes XSS attacks in description', async () => {
    const { token } = await login(app, {
      email: 'accountant@' + config.get<string>('application.domain'),
      password: 'i am an awesome accountant'
    })
    const accountingHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
    const original = (await request(app).get('/api/Products/1')).body.data
    const res = await request(app)
      .put('/api/Products/1')
      .set(accountingHeader)
      .send({ price: original.price, description: 'Tasty<iframe src="javascript:alert(`xss`)"></iframe> juice' })
    assert.equal(res.status, 200)
    assert.equal(res.body.data.price, original.price)
    assert.ok(!res.body.data.description.includes('<iframe'))
    assert.ok(res.body.data.description.includes('Tasty'))
    await request(app)
      .put('/api/Products/1')
      .set(accountingHeader)
      .send({ description: original.description })
  })

  void it('PUT update existing product is allowed for admins and sanitizes XSS attacks in description', async () => {
    const { token } = await login(app, {
      email: 'admin@' + config.get<string>('application.domain'),
      password: 'admin123'
    })
    const adminHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
    const original = (await request(app).get('/api/Products/1')).body.data
    const res = await request(app)
      .put('/api/Products/1')
      .set(adminHeader)
      .send({ description: '<img src=x onerror=alert(1)>Fresh juice' })
    assert.equal(res.status, 200)
    assert.ok(!res.body.data.description.includes('onerror'))
    assert.ok(res.body.data.description.includes('Fresh juice'))
    await request(app)
      .put('/api/Products/1')
      .set(adminHeader)
      .send({ description: original.description })
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
