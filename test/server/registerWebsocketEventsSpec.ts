/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import registerWebsocketEvents from '../../lib/startup/registerWebsocketEvents'
import { EventEmitter } from 'node:events'
import http from 'node:http'
import chai from 'chai'
const expect = chai.expect

describe('registerWebsocketEvents', () => {
  let server: http.Server

  beforeEach(() => {
    server = http.createServer()
    registerWebsocketEvents(server)
  })

  afterEach(() => {
    const io = (global as any).io
    io?.close()
    server.close()
  })

  it('handles socket error events instead of letting them crash the process', () => {
    const socket = new EventEmitter() as EventEmitter & { id: string }
    socket.id = 'socket-under-test'
    const connectionHandler = (global as any).io.sockets.listeners('connection')[0]
    connectionHandler(socket)

    expect(socket.listenerCount('error')).to.be.above(0)
    expect(() => socket.emit('error', new Error('websocket boom'))).to.not.throw()
  })
})
