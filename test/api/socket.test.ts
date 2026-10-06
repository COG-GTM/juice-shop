/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import type { Express } from 'express'
import * as http from 'http'
import ioClient from 'socket.io-client'
import { createTestApp } from './helpers/setup'
import registerWebsocketEvents from '../../lib/startup/registerWebsocketEvents'
import { challenges, notifications } from '../../data/datacache'
import * as security from '../../lib/insecurity'

let app: Express
let server: http.Server
let serverPort: number

before(async () => {
  const result = await createTestApp()
  app = result.app
  await new Promise<void>((resolve) => {
    server = http.createServer(app)
    registerWebsocketEvents(server)
    server.listen(0, () => {
      const addr = server.address()
      if (addr && typeof addr === 'object') {
        serverPort = addr.port
      }
      resolve()
    })
  })
}, { timeout: 60000 })

after(() => {
  if (server) {
    server.close()
  }
})

void describe('WebSocket', () => {
  let socket: ReturnType<typeof ioClient>

  beforeEach(async () => {
    await new Promise<void>((resolve) => {
      socket = ioClient(`http://localhost:${serverPort}`, {
        reconnectionDelay: 0,
        forceNew: true
      })
      socket.on('connect', () => {
        resolve()
      })
    })
  })

  afterEach(() => {
    if (socket.connected) {
      socket.disconnect()
    }
  })

  void it('server handles confirmation messages for emitted challenge resolutions', () => {
    socket.emit('notification received', 'Find the carefully hidden \'Score Board\' page.')
    socket.emit('notification received', 'Provoke an error that is not very gracefully handled.')
    socket.emit('notification received', 'Log in with the administrator\'s user account.')
    socket.emit('notification received', 'Retrieve a list of all user credentials via SQL Injection')
    socket.emit('notification received', 'Post some feedback in another user\'s name.')
    socket.emit('notification received', 'Wherever you go, there you are.')
    socket.emit('notification received', 'Place an order that makes you rich.')
    socket.emit('notification received', 'Access a confidential document.')
    socket.emit('notification received', 'Access a salesman\'s forgotten backup file.')
    socket.emit('notification received', 'Change Bender\'s password into slurmCl4ssic.')
    socket.emit('notification received', 'Apply some advanced cryptanalysis to find the real easter egg.')
    assert.ok(true)
  })

  void it('server handles confirmation message for a non-existent challenge', () => {
    socket.emit('notification received', 'Emit a confirmation for a challenge that was never emitted!')
    assert.ok(true)
  })

  void it('server handles empty confirmation message', () => {
    socket.emit('notification received', undefined)
    assert.ok(true)
  })
})

type ClientSocket = ReturnType<typeof ioClient>

const connect = async (auth?: Record<string, string>) => {
  return await new Promise<{ socket: ClientSocket, flags: string[] }>((resolve) => {
    const flags: string[] = []
    const socket = ioClient(`http://localhost:${serverPort}`, { reconnectionDelay: 0, forceNew: true, auth } as any)
    socket.on('challenge solved', (notification: any) => { flags.push(notification.flag) })
    socket.on('connect', () => { resolve({ socket, flags }) })
  })
}

const settle = async (ms = 300) => { await new Promise((resolve) => setTimeout(resolve, ms)) }

const addNotification = (flag: string) => {
  notifications.push({ key: 'regressionTest', name: 'Regression Test', challenge: 'Regression Test', flag, hidden: false, isRestore: false })
}

void describe('WebSocket notification acknowledgement', () => {
  void it('acknowledgement by one anonymous client does not remove the notification for other clients', async () => {
    addNotification('regression-flag-anonymous')
    const attacker = await connect()
    attacker.socket.emit('notification received', 'regression-flag-anonymous')
    await settle()
    attacker.socket.disconnect()

    const victim = await connect()
    await settle()
    victim.socket.disconnect()

    assert.ok(notifications.some(({ flag }) => flag === 'regression-flag-anonymous'))
    assert.ok(victim.flags.includes('regression-flag-anonymous'))
  })

  void it('acknowledgement is remembered only for the acknowledging client id', async () => {
    addNotification('regression-flag-client')
    const first = await connect({ clientId: 'a'.repeat(32) })
    first.socket.emit('notification received', 'regression-flag-client')
    await settle()
    first.socket.disconnect()

    const sameClient = await connect({ clientId: 'a'.repeat(32) })
    const otherClient = await connect({ clientId: 'b'.repeat(32) })
    await settle()
    sameClient.socket.disconnect()
    otherClient.socket.disconnect()

    assert.ok(!sameClient.flags.includes('regression-flag-client'))
    assert.ok(otherClient.flags.includes('regression-flag-client'))
  })
})

void describe('WebSocket challenge verification', () => {
  const xssPayload = '<iframe src="javascript:alert(`xss`)">'

  void it('anonymous socket cannot solve challenges', async () => {
    const { socket } = await connect()
    socket.emit('verifyLocalXssChallenge', xssPayload)
    socket.emit('verifyCloseNotificationsChallenge', [{}, {}])
    await settle()
    socket.disconnect()

    assert.equal(challenges.localXssChallenge.solved, false)
    assert.equal(challenges.closeNotificationsChallenge.solved, false)
  })

  void it('socket with a signed but unregistered token cannot solve challenges', async () => {
    const { socket } = await connect({ token: security.authorize({ data: { id: 1, email: 'admin@juice-sh.op' } }) })
    socket.emit('verifyLocalXssChallenge', xssPayload)
    await settle()
    socket.disconnect()

    assert.equal(challenges.localXssChallenge.solved, false)
  })

  void it('socket authenticated with a valid token can solve challenges', async () => {
    const user = { data: { id: 1, email: 'admin@juice-sh.op' } }
    const token = security.authorize(user)
    security.authenticatedUsers.put(token, user as any)
    const { socket } = await connect({ token })
    socket.emit('verifyLocalXssChallenge', xssPayload)
    socket.emit('verifyCloseNotificationsChallenge', [{}, {}])
    await settle()
    socket.disconnect()

    assert.equal(challenges.localXssChallenge.solved, true)
    assert.equal(challenges.closeNotificationsChallenge.solved, true)
  })
})
