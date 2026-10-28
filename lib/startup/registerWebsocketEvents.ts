/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import * as utils from '../utils'
import { Server } from 'socket.io'
import jws from 'jws'
import { notifications, challenges } from '../../data/datacache'
import * as challengeUtils from '../challengeUtils'
import * as security from '../insecurity'

let firstConnectedSocket: any = null

const globalWithSocketIO = global as typeof globalThis & {
  io: SocketIOClientStatic & Server
}

const CLIENT_ID_PATTERN = /^[a-f0-9]{32}$/
const MAX_TRACKED_CLIENTS = 1000
const acknowledgedNotifications = new Map<string, Set<string>>()

export const socketUserFrom = (handshake: any): { id: number } | undefined => {
  const token = handshake?.auth?.token
  if (typeof token !== 'string' || jws.decode(token)?.header?.alg !== 'RS256' || !security.verify(token)) return undefined
  const payload = security.decode(token) as { exp?: number, data?: { id?: number } } | undefined
  if (typeof payload?.exp === 'number' && payload.exp * 1000 <= Date.now()) return undefined
  return typeof payload?.data?.id === 'number' ? { id: payload.data.id } : undefined
}

export const socketClientKeyOf = (socket: any) => {
  const clientId = socket?.handshake?.auth?.clientId
  return typeof clientId === 'string' && CLIENT_ID_PATTERN.test(clientId) ? `client:${clientId}` : `socket:${socket.id}`
}

const acknowledge = (clientKey: string, flag: string) => {
  let acknowledged = acknowledgedNotifications.get(clientKey)
  if (!acknowledged) {
    if (acknowledgedNotifications.size >= MAX_TRACKED_CLIENTS) {
      acknowledgedNotifications.delete(acknowledgedNotifications.keys().next().value as string)
    }
    acknowledged = new Set<string>()
    acknowledgedNotifications.set(clientKey, acknowledged)
  }
  acknowledged.add(flag)
}

const registerWebsocketEvents = (server: any) => {
  const io = new Server(server, { cors: { origin: 'http://localhost:4200' } })
  // @ts-expect-error FIXME Type safety issue when setting global socket-io object
  globalWithSocketIO.io = io

  io.on('connection', (socket: any) => {
    if (firstConnectedSocket === null) {
      socket.emit('server started')
      firstConnectedSocket = socket.id
    }

    const user = socketUserFrom(socket.handshake)
    const clientKey = socketClientKeyOf(socket)

    notifications.forEach((notification: any) => {
      if (!acknowledgedNotifications.get(clientKey)?.has(notification.flag)) {
        socket.emit('challenge solved', notification)
      }
    })

    socket.on('notification received', (data: any) => {
      if (typeof data === 'string' && notifications.some(({ flag }: any) => flag === data)) {
        acknowledge(clientKey, data)
      }
    })

    socket.on('disconnect', () => {
      if (clientKey.startsWith('socket:')) {
        acknowledgedNotifications.delete(clientKey)
      }
    })

    socket.on('verifyLocalXssChallenge', (data: any) => {
      if (!user || typeof data !== 'string') return
      challengeUtils.solveIf(challenges.localXssChallenge, () => { return utils.contains(data, '<iframe src="javascript:alert(`xss`)">') })
      challengeUtils.solveIf(challenges.xssBonusChallenge, () => { return utils.contains(data, config.get('challenges.xssBonusPayload')) })
    })

    socket.on('verifySvgInjectionChallenge', (data: any) => {
      if (!user || typeof data !== 'string') return
      challengeUtils.solveIf(challenges.svgInjectionChallenge, () => { return data?.match(/.*\.\.\/\.\.\/\.\.[\w/-]*?\/redirect\?to=https?:\/\/placecats.com\/(g\/)?[\d]+\/[\d]+.*/) && security.isRedirectAllowed(data) })
    })

    socket.on('verifyCloseNotificationsChallenge', (data: any) => {
      if (!user) return
      challengeUtils.solveIf(challenges.closeNotificationsChallenge, () => { return Array.isArray(data) && data.length > 1 })
    })
  })
}

export default registerWebsocketEvents
