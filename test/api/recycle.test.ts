/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'

let app: Express
let authHeader: { Authorization: string, 'content-type': string }
let otherAuthHeader: { Authorization: string, 'content-type': string }
let otherUserId: number
let addressId: number
let recycleId: number

before(async () => {
  const result = await createTestApp()
  app = result.app

  const { token } = await login(app, {
    email: 'jim@juice-sh.op',
    password: 'ncc-1701'
  })
  authHeader = {
    Authorization: 'Bearer ' + token,
    'content-type': 'application/json'
  }

  const registerRes = await register(app, {
    email: 'recycle-tester@example.com',
    password: 'recycle-test'
  })
  otherUserId = registerRes.body.data.id
  const { token: otherToken } = await login(app, {
    email: 'recycle-tester@example.com',
    password: 'recycle-test'
  })
  otherAuthHeader = {
    Authorization: 'Bearer ' + otherToken,
    'content-type': 'application/json'
  }

  const addressRes = await request(app)
    .post('/api/Addresss')
    .set(authHeader)
    .send({
      fullName: 'Jim',
      mobileNum: '9800000000',
      zipCode: 'NX 101',
      streetAddress: 'Bakers Street',
      city: 'NYC',
      state: 'NY',
      country: 'USA'
    })
  addressId = addressRes.body.data.id
}, { timeout: 60000 })

void describe('/api/Recycles', () => {
  void it('POST new recycle with an address owned by the caller', async () => {
    const res = await request(app)
      .post('/api/Recycles')
      .set(authHeader)
      .send({
        quantity: 200,
        AddressId: `${addressId}`,
        isPickup: true,
        date: '2017-05-31'
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.data.id, 'number')
    assert.equal(res.body.data.AddressId, addressId)
    assert.equal(typeof res.body.data.createdAt, 'string')
    assert.equal(typeof res.body.data.updatedAt, 'string')
    recycleId = res.body.data.id
  })

  void it('POST new recycle is forbidden via public API', async () => {
    const res = await request(app)
      .post('/api/Recycles')
      .send({
        quantity: 200,
        AddressId: '1',
        isPickup: true,
        date: '2017-05-31'
      })
    assert.equal(res.status, 401)
  })

  void it('POST new recycle for another user\'s address is forbidden', async () => {
    const res = await request(app)
      .post('/api/Recycles')
      .set(otherAuthHeader)
      .send({
        quantity: 200,
        AddressId: `${addressId}`,
        isPickup: true,
        date: '2017-05-31'
      })
    assert.equal(res.status, 403)
  })

  void it('POST new recycle with forged UserId is attributed to the caller', async () => {
    const res = await request(app)
      .post('/api/Recycles')
      .set(otherAuthHeader)
      .send({
        quantity: 200,
        UserId: 1,
        isPickup: false,
        date: '2017-06-01'
      })
    assert.equal(res.status, 201)
    assert.equal(res.body.data.UserId, otherUserId)
  })

  void it('Will prevent GET all recycles from this endpoint', async () => {
    const res = await request(app)
      .get('/api/Recycles')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.err, 'Sorry, this endpoint is not supported.')
  })

  void it('GET recycle is forbidden via public API', async () => {
    const res = await request(app)
      .get(`/api/Recycles/${recycleId}`)
    assert.equal(res.status, 401)
  })

  void it('Will GET existing recycle owned by the caller', async () => {
    const res = await request(app)
      .get(`/api/Recycles/${recycleId}`)
      .set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    const items = res.body.data
    assert.ok(Array.isArray(items))
    for (const item of items) {
      assert.equal(typeof item.id, 'number')
      assert.equal(typeof item.UserId, 'number')
      assert.equal(typeof item.AddressId, 'number')
      assert.equal(typeof item.quantity, 'number')
      assert.equal(typeof item.isPickup, 'boolean')
      assert.ok(item.date !== undefined)
      assert.equal(typeof item.createdAt, 'string')
      assert.equal(typeof item.updatedAt, 'string')
    }
  })

  void it('GET recycle owned by another user returns nothing', async () => {
    const res = await request(app)
      .get(`/api/Recycles/${recycleId}`)
      .set(otherAuthHeader)
    assert.equal(res.status, 200)
    assert.ok(Array.isArray(res.body.data))
    assert.equal(res.body.data.length, 0)
  })

  void it('PUT update existing recycle is forbidden', async () => {
    const res = await request(app)
      .put(`/api/Recycles/${recycleId}`)
      .set(authHeader)
      .send({
        quantity: 100000
      })
    assert.equal(res.status, 401)
  })

  void it('DELETE existing recycle is forbidden', async () => {
    const res = await request(app)
      .delete(`/api/Recycles/${recycleId}`)
      .set(authHeader)
    assert.equal(res.status, 401)
  })
})
