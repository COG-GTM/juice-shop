/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import * as http from 'node:http'
import { type AddressInfo } from 'node:net'
import ioClient from 'socket.io-client'
import { challenges } from '../../data/datacache'
import { type Challenge } from 'data/types'
import registerWebsocketEvents from '../../lib/startup/registerWebsocketEvents'

const expect = chai.expect

const unsolved = () => ({ solved: false, save: () => ({ then () {} }) }) as unknown as Challenge

describe('registerWebsocketEvents', () => {
  let server: http.Server
  let port: number
  let socket: ReturnType<typeof ioClient>

  before((done) => {
    server = http.createServer((req, res) => { res.end('ok') })
    registerWebsocketEvents(server)
    server.listen(0, () => {
      port = (server.address() as AddressInfo).port
      done()
    })
  })

  after((done) => {
    (global as any).io?.close()
    server.close(() => { done() })
  })

  beforeEach((done) => {
    challenges.localXssChallenge = unsolved()
    challenges.xssBonusChallenge = unsolved()
    challenges.svgInjectionChallenge = unsolved()
    challenges.closeNotificationsChallenge = unsolved()
    socket = ioClient(`http://localhost:${port}`, { forceNew: true, reconnection: false, transports: ['websocket'] })
    socket.on('connect', () => { done() })
  })

  afterEach(() => {
    socket.disconnect()
  })

  const roundTrip = async () => {
    await new Promise((resolve) => setTimeout(resolve, 100))
    return await new Promise<string>((resolve, reject) => {
      http.get(`http://localhost:${port}/`, (res) => {
        let body = ''
        res.on('data', (chunk) => { body += chunk })
        res.on('end', () => { resolve(body) })
      }).on('error', reject)
    })
  }

  it('keeps serving requests after non-string verifySvgInjectionChallenge and verifyLocalXssChallenge payloads', async () => {
    socket.emit('verifySvgInjectionChallenge', 1)
    socket.emit('verifyLocalXssChallenge', {})
    for (const data of [1, {}, [], true, { includes: 'x', match: 'y' }]) {
      socket.emit('verifySvgInjectionChallenge', data)
      socket.emit('verifyLocalXssChallenge', data)
      socket.emit('verifyCloseNotificationsChallenge', data)
      socket.emit('notification received', data)
    }
    expect(await roundTrip()).to.equal('ok')
    expect(socket.connected).to.equal(true)
    expect(challenges.svgInjectionChallenge.solved).to.equal(false)
    expect(challenges.localXssChallenge.solved).to.equal(false)
  })

  it('stays responsive after oversized verifySvgInjectionChallenge and verifyLocalXssChallenge payloads', async () => {
    const long = 'a'.repeat(900 * 1024)
    const started = Date.now()
    socket.emit('verifySvgInjectionChallenge', long)
    socket.emit('verifyLocalXssChallenge', long)
    expect(await roundTrip()).to.equal('ok')
    expect(Date.now() - started).to.be.below(1000)
    expect(socket.connected).to.equal(true)
  })

  it('ignores oversized payloads even when they contain a solving string', async () => {
    const padding = 'a'.repeat(11 * 1024)
    socket.emit('verifyLocalXssChallenge', '<iframe src="javascript:alert(`xss`)">' + padding)
    socket.emit('verifySvgInjectionChallenge', '../../..//redirect?to=https://placecats.com/g/200/100?x=https://github.com/juice-shop/juice-shop' + padding)
    await roundTrip()
    expect(challenges.localXssChallenge.solved).to.equal(false)
    expect(challenges.svgInjectionChallenge.solved).to.equal(false)
  })

  it('still solves localXssChallenge for a string payload', async () => {
    socket.emit('verifyLocalXssChallenge', '<iframe src="javascript:alert(`xss`)">')
    await roundTrip()
    expect(challenges.localXssChallenge.solved).to.equal(true)
  })

  it('still solves svgInjectionChallenge for a string payload', async () => {
    socket.emit('verifySvgInjectionChallenge', '../../..//redirect?to=https://placecats.com/g/200/100?x=https://github.com/juice-shop/juice-shop')
    await roundTrip()
    expect(challenges.svgInjectionChallenge.solved).to.equal(true)
  })

  it('still solves closeNotificationsChallenge for an array payload', async () => {
    socket.emit('verifyCloseNotificationsChallenge', [{}, {}])
    await roundTrip()
    expect(challenges.closeNotificationsChallenge.solved).to.equal(true)
  })
})
