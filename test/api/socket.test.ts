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
import * as challengeUtils from '../../lib/challengeUtils'
import * as security from '../../lib/insecurity'
import { notifications } from '../../data/datacache'

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

void describe('WebSocket challenge notifications', () => {
  const sockets: Array<ReturnType<typeof ioClient>> = []
  const unsignedToken = (payload: object) => `${Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.`

  const connect = async (auth?: object) => {
    const socket = ioClient(`http://localhost:${serverPort}`, { reconnectionDelay: 0, forceNew: true, auth } as any)
    sockets.push(socket)
    await new Promise<void>((resolve) => { socket.on('connect', () => { resolve() }) })
    return socket
  }

  const nextNotification = async (socket: ReturnType<typeof ioClient>, key: string) => {
    return await new Promise<any>((resolve) => {
      const listener = (notification: any) => {
        if (notification.key === key) {
          socket.off('challenge solved', listener)
          resolve(notification)
        }
      }
      socket.on('challenge solved', listener)
    })
  }

  const replayedNotification = async (key: string, auth?: object) => {
    const socket = ioClient(`http://localhost:${serverPort}`, { reconnectionDelay: 0, forceNew: true, auth } as any)
    sockets.push(socket)
    return await nextNotification(socket, key)
  }

  const solvedChallenge = (key: string) => ({ key, name: key, description: 'Test challenge', solved: true }) as any

  beforeEach(() => {
    notifications.splice(0)
  })

  afterEach(() => {
    sockets.splice(0).forEach(socket => socket.disconnect())
    notifications.splice(0)
  })

  void it('anonymous sockets receive solved notifications without the flag', async () => {
    const socket = await connect()
    const received = nextNotification(socket, 'anonymousViewerTest')
    challengeUtils.sendNotification(solvedChallenge('anonymousViewerTest'), false, undefined)
    const notification = await received
    assert.equal(notification.flag, undefined)
    assert.equal(notification.solverId, undefined)
  })

  void it('forged unsigned tokens are treated as anonymous', async () => {
    const socket = await connect({ token: unsignedToken({ data: { id: 1 }, exp: 9999999999 }) })
    const received = nextNotification(socket, 'unsignedTokenTest')
    challengeUtils.sendNotification(solvedChallenge('unsignedTokenTest'), false, undefined)
    assert.equal((await received).flag, undefined)
  })

  void it('only the solving user receives the flag of an attributed challenge', async () => {
    const solver = await connect({ token: security.authorize({ data: { id: 1 } }) })
    const otherUser = await connect({ token: security.authorize({ data: { id: 2 } }) })
    const solverReceived = nextNotification(solver, 'attributedSolveTest')
    const otherReceived = nextNotification(otherUser, 'attributedSolveTest')
    challengeUtils.sendNotification(solvedChallenge('attributedSolveTest'), false, 1)
    assert.ok((await solverReceived).flag)
    assert.equal((await otherReceived).flag, undefined)
  })

  void it('pending notifications are replayed to new sockets without the flag of other users', async () => {
    challengeUtils.sendNotification(solvedChallenge('replayTest'), false, 1)
    assert.equal((await replayedNotification('replayTest')).flag, undefined)
    assert.ok((await replayedNotification('replayTest', { token: security.authorize({ data: { id: 1 } }) })).flag)
  })

  void it('acknowledging a notification does not remove it for other clients', async () => {
    challengeUtils.sendNotification(solvedChallenge('acknowledgeTest'), false, undefined)
    const pending = notifications.length
    const socket = await connect({ clientId: 'a'.repeat(32) })
    socket.emit('notification received', 'acknowledgeTest')
    await new Promise(resolve => setTimeout(resolve, 100))
    assert.equal(notifications.length, pending)
    assert.equal((await replayedNotification('acknowledgeTest', { clientId: 'b'.repeat(32) })).key, 'acknowledgeTest')
  })

  void it('a restored challenge is attributed to the restoring user while repeats keep the original solver', async () => {
    challengeUtils.sendNotification(solvedChallenge('restoreTest'), false, 1)
    challengeUtils.sendNotification(solvedChallenge('restoreTest'), true, 2, false)
    assert.ok((await replayedNotification('restoreTest', { token: security.authorize({ data: { id: 2 } }) })).flag)
    challengeUtils.sendNotification(solvedChallenge('restoreTest'), true, 3)
    assert.ok((await replayedNotification('restoreTest', { token: security.authorize({ data: { id: 2 } }) })).flag)
  })

  void it('repeated notifications of the same challenge are retained only once', () => {
    challengeUtils.sendNotification(solvedChallenge('repeatTest'), false, 1)
    challengeUtils.sendNotification(solvedChallenge('repeatTest'), true, 1)
    challengeUtils.sendNotification(solvedChallenge('repeatTest'), true, 1)
    assert.equal(notifications.filter(({ key }) => key === 'repeatTest').length, 1)
  })
})
