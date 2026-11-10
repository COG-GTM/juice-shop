/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import path from 'node:path'
import { randomUUID } from 'node:crypto'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/user/data-export', () => {
  void it('Export data without use of CAPTCHA', async () => {
    const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const res = await request(app)
      .post('/rest/user/data-export')
      .set(authHeader)
      .send({ format: '1' })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.confirmation, 'Your data export will open in a new Browser window.')
    const parsedData = JSON.parse(res.body.userData)
    assert.equal(parsedData.username, 'bkimminich')
    assert.equal(parsedData.email, 'bjoern.kimminich@gmail.com')
  })

  void it('Export data when CAPTCHA requested need right answer', async () => {
    const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const captchaRes = await request(app)
      .get('/rest/image-captcha')
      .set(authHeader)

    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const res = await request(app)
      .post('/rest/user/data-export')
      .set(authHeader)
      .send({ answer: 'AAAAAA', format: 1 })

    assert.equal(res.status, 401)
    assert.ok(res.text.includes('Wrong answer to CAPTCHA. Please try again.'))
  })

  void it('Export data using right answer to CAPTCHA', async () => {
    const { token } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const captchaRes = await request(app)
      .get('/rest/image-captcha')
      .set(authHeader)

    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const res = await request(app)
      .post('/rest/user/data-export')
      .set(authHeader)
      .send({ answer: captchaRes.body.answer, format: 1 })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.confirmation, 'Your data export will open in a new Browser window.')
    const parsedData = JSON.parse(res.body.userData)
    assert.equal(parsedData.username, 'bkimminich')
    assert.equal(parsedData.email, 'bjoern.kimminich@gmail.com')
  })

  void it('Export data including orders without use of CAPTCHA', async () => {
    const { token } = await login(app, { email: 'amy@' + config.get<string>('application.domain'), password: 'K1f.....................' })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    await request(app)
      .post('/rest/basket/4/checkout')
      .set(authHeader)

    const res = await request(app)
      .post('/rest/user/data-export')
      .set(authHeader)
      .send({ format: '1' })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.confirmation, 'Your data export will open in a new Browser window.')
    const parsedData = JSON.parse(res.body.userData)
    assert.equal(parsedData.username, '')
    assert.equal(parsedData.email, 'amy@' + config.get<string>('application.domain'))
    assert.equal(parsedData.orders[0].totalPrice, 9.98)
    assert.equal(parsedData.orders[0].bonus, 0)
    assert.equal(parsedData.orders[0].products[0].quantity, 2)
    assert.equal(parsedData.orders[0].products[0].name, 'Raspberry Juice (1000ml)')
    assert.equal(parsedData.orders[0].products[0].price, 4.99)
    assert.equal(parsedData.orders[0].products[0].total, 9.98)
    assert.equal(parsedData.orders[0].products[0].bonus, 0)
  })

  void it('Export data including reviews without use of CAPTCHA', async () => {
    const { token } = await login(app, { email: 'jim@' + config.get<string>('application.domain'), password: 'ncc-1701' })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const res = await request(app)
      .post('/rest/user/data-export')
      .set(authHeader)
      .send({ format: '1' })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.confirmation, 'Your data export will open in a new Browser window.')
    const parsedData = JSON.parse(res.body.userData)
    assert.equal(parsedData.username, '')
    assert.equal(parsedData.email, 'jim@' + config.get<string>('application.domain'))
    assert.equal(parsedData.reviews[0].message, 'Looks so much better on my uniform than the boring Starfleet symbol.')
    assert.equal(parsedData.reviews[0].author, 'jim@' + config.get<string>('application.domain'))
    assert.equal(parsedData.reviews[0].productId, 20)
    assert.equal(parsedData.reviews[0].likesCount, 0)
    assert.equal(parsedData.reviews[0].likedBy[0], undefined)
    assert.equal(parsedData.reviews[1].message, 'Fresh out of a replicator.')
    assert.equal(parsedData.reviews[1].author, 'jim@' + config.get<string>('application.domain'))
    assert.equal(parsedData.reviews[1].productId, 22)
    assert.equal(parsedData.reviews[1].likesCount, 0)
    assert.equal(parsedData.reviews[1].likedBy[0], undefined)
  })

  void it('Export data including memories without use of CAPTCHA', async () => {
    const { token } = await login(app, { email: 'jim@' + config.get<string>('application.domain'), password: 'ncc-1701' })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const file = path.resolve(__dirname, '../files/validProfileImage.jpg')

    await request(app)
      .post('/rest/memories')
      .set('Authorization', 'Bearer ' + token)
      .attach('image', file, 'Valid Image')
      .field('caption', 'Valid Image')

    const res = await request(app)
      .post('/rest/user/data-export')
      .set(authHeader)
      .send({ format: '1' })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.confirmation, 'Your data export will open in a new Browser window.')
    const parsedData = JSON.parse(res.body.userData)
    assert.equal(parsedData.username, '')
    assert.equal(parsedData.email, 'jim@' + config.get<string>('application.domain'))
    assert.equal(parsedData.memories[0].caption, 'Valid Image')
    assert.ok(parsedData.memories[0].imageUrl.includes('assets/public/images/uploads/valid-image'))
  })

  void it('Export data including orders with use of CAPTCHA', async () => {
    const { token } = await login(app, { email: 'amy@' + config.get<string>('application.domain'), password: 'K1f.....................' })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    await request(app)
      .post('/rest/basket/4/checkout')
      .set(authHeader)

    const captchaRes = await request(app)
      .get('/rest/image-captcha')
      .set(authHeader)

    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const res = await request(app)
      .post('/rest/user/data-export')
      .set(authHeader)
      .send({ answer: captchaRes.body.answer, format: 1 })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.confirmation, 'Your data export will open in a new Browser window.')
    const parsedData = JSON.parse(res.body.userData)
    assert.equal(parsedData.username, '')
    assert.equal(parsedData.email, 'amy@' + config.get<string>('application.domain'))
    assert.equal(parsedData.orders[0].totalPrice, 9.98)
    assert.equal(parsedData.orders[0].bonus, 0)
    assert.equal(parsedData.orders[0].products[0].quantity, 2)
    assert.equal(parsedData.orders[0].products[0].name, 'Raspberry Juice (1000ml)')
    assert.equal(parsedData.orders[0].products[0].price, 4.99)
    assert.equal(parsedData.orders[0].products[0].total, 9.98)
    assert.equal(parsedData.orders[0].products[0].bonus, 0)
  })

  void it('Export data including reviews with use of CAPTCHA', async () => {
    const { token } = await login(app, { email: 'jim@' + config.get<string>('application.domain'), password: 'ncc-1701' })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const captchaRes = await request(app)
      .get('/rest/image-captcha')
      .set(authHeader)

    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const res = await request(app)
      .post('/rest/user/data-export')
      .set(authHeader)
      .send({ answer: captchaRes.body.answer, format: 1 })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.confirmation, 'Your data export will open in a new Browser window.')
    const parsedData = JSON.parse(res.body.userData)
    assert.equal(parsedData.username, '')
    assert.equal(parsedData.email, 'jim@' + config.get<string>('application.domain'))
    assert.equal(parsedData.reviews[0].message, 'Looks so much better on my uniform than the boring Starfleet symbol.')
    assert.equal(parsedData.reviews[0].author, 'jim@' + config.get<string>('application.domain'))
    assert.equal(parsedData.reviews[0].productId, 20)
    assert.equal(parsedData.reviews[0].likesCount, 0)
    assert.equal(parsedData.reviews[0].likedBy[0], undefined)
    assert.equal(parsedData.reviews[1].message, 'Fresh out of a replicator.')
    assert.equal(parsedData.reviews[1].author, 'jim@' + config.get<string>('application.domain'))
    assert.equal(parsedData.reviews[1].productId, 22)
    assert.equal(parsedData.reviews[1].likesCount, 0)
    assert.equal(parsedData.reviews[1].likedBy[0], undefined)
  })

  void it('Export data including memories with use of CAPTCHA', async () => {
    const { token } = await login(app, { email: 'jim@' + config.get<string>('application.domain'), password: 'ncc-1701' })
    const authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

    const file = path.resolve(__dirname, '../files/validProfileImage.jpg')

    await request(app)
      .post('/rest/memories')
      .set('Authorization', 'Bearer ' + token)
      .attach('image', file, 'Valid Image')
      .field('caption', 'Valid Image')

    const captchaRes = await request(app)
      .get('/rest/image-captcha')
      .set(authHeader)

    assert.equal(captchaRes.status, 200)
    assert.ok(captchaRes.headers['content-type']?.includes('application/json'))

    const res = await request(app)
      .post('/rest/user/data-export')
      .set(authHeader)
      .send({ answer: captchaRes.body.answer, format: 1 })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.confirmation, 'Your data export will open in a new Browser window.')
    const parsedData = JSON.parse(res.body.userData)
    assert.equal(parsedData.username, '')
    assert.equal(parsedData.email, 'jim@' + config.get<string>('application.domain'))
    assert.equal(parsedData.memories[0].caption, 'Valid Image')
    assert.ok(parsedData.memories[0].imageUrl.includes('assets/public/images/uploads/valid-image'))
  })

  void it('Export data escapes HTML from review messages', async () => {
    const victim = await registerAndLogin(`victim-${randomUUID()}@juice-sh.op`)
    const payload = "<img src=x onerror='alert(1)'> & more"

    await request(app)
      .put('/rest/products/1/reviews')
      .set(victim.authHeader)
      .send({ message: payload, author: victim.email })
      .expect(201)

    const res = await request(app)
      .post('/rest/user/data-export')
      .set(victim.authHeader)
      .send({ format: '1' })

    assert.equal(res.status, 200)
    assert.ok(!/[<>&]/.test(res.body.userData))
    const parsedData = JSON.parse(res.body.userData)
    assert.ok(parsedData.reviews.some(({ message }: { message: string }) => message === payload))
  })

  void it('Export data escapes HTML from emails of users who liked a review', async () => {
    const victim = await registerAndLogin(`victim-${randomUUID()}@juice-sh.op`)
    const marker = randomUUID()
    await request(app)
      .put('/rest/products/2/reviews')
      .set(victim.authHeader)
      .send({ message: marker, author: victim.email })
      .expect(201)
    const reviews = await request(app).get('/rest/products/2/reviews')
    const reviewId = reviews.body.data.find(({ message }: { message: string }) => message === marker)._id

    const attacker = await registerAndLogin(`<img src=x onerror=alert(1)>${marker}`)
    await request(app)
      .post('/rest/products/reviews')
      .set(attacker.authHeader)
      .send({ id: reviewId })
      .expect(200)

    const res = await request(app)
      .post('/rest/user/data-export')
      .set(victim.authHeader)
      .send({ format: '1' })

    assert.equal(res.status, 200)
    assert.ok(!/[<>&]/.test(res.body.userData))
    const parsedData = JSON.parse(res.body.userData)
    assert.ok(parsedData.reviews.some(({ likedBy }: { likedBy: string[] }) => likedBy.includes(attacker.email)))
  })

  void it('Export data escapes HTML from memory captions', async () => {
    const victim = await registerAndLogin(`victim-${randomUUID()}@juice-sh.op`)
    const caption = '<img src=x onerror=alert(1)> & more'

    await request(app)
      .post('/rest/memories')
      .set('Authorization', victim.authHeader.Authorization)
      .attach('image', path.resolve(__dirname, '../files/validProfileImage.jpg'), 'Valid Image')
      .field('caption', caption)
      .expect(200)

    const res = await request(app)
      .post('/rest/user/data-export')
      .set(victim.authHeader)
      .send({ format: '1' })

    assert.equal(res.status, 200)
    assert.ok(!/[<>&]/.test(res.body.userData))
    const parsedData = JSON.parse(res.body.userData)
    assert.equal(parsedData.memories[0].caption, caption)
  })

  void it('Export data escapes HTML from usernames', async () => {
    const credential = randomUUID()
    const email = `victim-${randomUUID()}@juice-sh.op`
    await request(app)
      .post('/api/Users')
      .set({ 'content-type': 'application/json' })
      .send({ email, password: credential, passwordRepeat: credential })
      .expect(201)
    const { token } = await login(app, { email, password: credential })

    await request(app)
      .post('/profile')
      .set('Cookie', `token=${token}`)
      .type('form')
      .send({ username: '<<a|ascript>alert(1)</script> & <b>bold</b>' })
      .redirects(0)
      .expect(302)

    const relogin = await login(app, { email, password: credential })
    const res = await request(app)
      .post('/rest/user/data-export')
      .set({ Authorization: 'Bearer ' + relogin.token, 'content-type': 'application/json' })
      .send({ format: '1' })

    assert.equal(res.status, 200)
    assert.ok(!/[<>&]/.test(res.body.userData))
    const parsedData = JSON.parse(res.body.userData)
    assert.ok(parsedData.username.includes('<'))
  })
})

async function registerAndLogin (email: string) {
  const credential = randomUUID()
  const registration = await request(app)
    .post('/api/Users')
    .set({ 'content-type': 'application/json' })
    .send({ email, password: credential, passwordRepeat: credential })
    .expect(201)
  const storedEmail: string = registration.body.data.email
  const { token } = await login(app, { email: storedEmail, password: credential })
  return { email: storedEmail, authHeader: { Authorization: 'Bearer ' + token, 'content-type': 'application/json' } }
}
