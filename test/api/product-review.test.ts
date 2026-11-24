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
import { type Product } from '../../data/types'
import * as security from '../../lib/insecurity'
import * as db from '../../data/mongodb'

let app: Express

const authHeader = { Authorization: `Bearer ${security.authorize()}`, 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/products/:id/reviews', () => {
  void it('GET product reviews by product id', async () => {
    const res = await request(app)
      .get('/rest/products/1/reviews')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    const review = res.body.data[0]
    assert.equal(typeof review.product, 'number')
    assert.equal(typeof review.message, 'string')
    assert.equal(typeof review.author, 'string')
  })

  void it('GET product reviews does not expose emails of users who liked a review', async () => {
    const { token } = await login(app, {
      email: 'jim@' + config.get<string>('application.domain'),
      password: 'ncc-1701'
    })
    const before = await request(app)
      .get('/rest/products/1/reviews')
    const likeRes = await request(app)
      .post('/rest/products/reviews')
      .set({ Authorization: `Bearer ${token}` })
      .send({ id: before.body.data[0]._id })
    assert.equal(likeRes.status, 200)

    const res = await request(app)
      .get('/rest/products/1/reviews')
    assert.equal(res.status, 200)
    for (const review of res.body.data) {
      assert.equal(review.likedBy, undefined)
      assert.equal(typeof review.likesCount, 'number')
      for (const key of Object.keys(review)) {
        assert.ok(['_id', 'product', 'message', 'author', 'likesCount', 'liked', 'editable'].includes(key), `unexpected field ${key}`)
      }
    }
    assert.ok(!JSON.stringify(res.body).includes('jim@'))
  })

  void it('GET product reviews does not expose author email addresses', async () => {
    const res = await request(app)
      .get('/rest/products/1/reviews')
    assert.equal(res.status, 200)
    assert.ok(res.body.data.length > 0)
    assert.ok(!JSON.stringify(res.body).includes('@'))
    for (const review of res.body.data) {
      assert.equal(review.editable, undefined)
    }
  })

  void it('GET product reviews marks only the logged-in author\'s own reviews as editable', async () => {
    const jimEmail = 'jim@' + config.get<string>('application.domain')
    const { token } = await login(app, {
      email: jimEmail,
      password: 'ncc-1701'
    })
    const message = 'Editable review check ' + Date.now()
    const putRes = await request(app)
      .put('/rest/products/2/reviews')
      .set({ Authorization: `Bearer ${token}` })
      .send({ message, author: jimEmail })
    assert.equal(putRes.status, 201)

    const res = await request(app)
      .get('/rest/products/2/reviews')
      .set({ Authorization: `Bearer ${token}` })
    assert.equal(res.status, 200)
    assert.ok(!JSON.stringify(res.body).includes('@'))
    const own = res.body.data.filter((review: { message: string }) => review.message === message)
    assert.equal(own.length, 1)
    assert.equal(own[0].editable, true)
    assert.notEqual(own[0].author, jimEmail)
    for (const review of res.body.data.filter((review: { message: string }) => review.message !== message)) {
      assert.equal(review.editable, undefined)
    }

    const anonRes = await request(app)
      .get('/rest/products/2/reviews')
    assert.ok(anonRes.body.data.every((review: { editable?: boolean }) => review.editable === undefined))

    await db.reviewsCollection.remove({ message })
  })

  void it('GET product reviews attack by injecting a mongoDB sleep command', async () => {
    const res = await request(app)
      .get('/rest/products/sleep(1)/reviews')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
  })

  // FIXME Turn on when #1960 is resolved
  void it.skip('GET product reviews by alphanumeric non-mongoDB-command product id', async () => {
    const res = await request(app)
      .get('/rest/products/kaboom/reviews')
    assert.equal(res.status, 400)
  })

  void it('PUT single product review can be created', async () => {
    const res = await request(app)
      .put('/rest/products/1/reviews')
      .send({
        message: 'Lorem Ipsum',
        author: 'Anonymous'
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
  })
})

void describe('/rest/products/reviews', () => {
  let reviewId: string

  before(async () => {
    const res = await request(app)
      .get('/rest/products/1/reviews')
    const response = res.body
    reviewId = response.data[0]._id
  })

  void it('PATCH single product review can be edited', async () => {
    const res = await request(app)
      .patch('/rest/products/reviews')
      .set(authHeader)
      .send({
        id: reviewId,
        message: 'Lorem Ipsum'
      })
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.modified, 'number')
    assert.ok(Array.isArray(res.body.original))
    assert.ok(Array.isArray(res.body.updated))
  })

  void it('PATCH single product review editing need an authenticated user', async () => {
    const res = await request(app)
      .patch('/rest/products/reviews')
      .send({
        id: reviewId,
        message: 'Lorem Ipsum'
      })
    assert.equal(res.status, 401)
  })

  void it('POST non-existing product review cannot be liked', async () => {
    const { token } = await login(app, {
      email: 'bjoern.kimminich@gmail.com',
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })
    const res = await request(app)
      .post('/rest/products/reviews')
      .set({ Authorization: `Bearer ${token}` })
      .send({
        id: 'does not exist'
      })
    assert.equal(res.status, 404)
  })

  void it('POST single product review can be liked', async () => {
    const { token } = await login(app, {
      email: 'bjoern.kimminich@gmail.com',
      password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
    })
    const res = await request(app)
      .post('/rest/products/reviews')
      .set({ Authorization: `Bearer ${token}` })
      .send({
        id: reviewId
      })
    assert.equal(res.status, 200)
  })

  void it('PATCH multiple product review via injection', async () => {
    const totalReviews = config.get<Product[]>('products').reduce((sum: number, { reviews = [] }: any) => sum + reviews.length, 1)

    const res = await request(app)
      .patch('/rest/products/reviews')
      .set(authHeader)
      .send({
        id: { $ne: -1 },
        message: 'trololololololololololololololololololololololololololol'
      })
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.modified, 'number')
    assert.ok(Array.isArray(res.body.original))
    assert.ok(Array.isArray(res.body.updated))
    assert.equal(res.body.modified, totalReviews)
  })
})
