/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import * as utils from '../utils'
import { Server } from 'socket.io'
import { notifications, challenges } from '../../data/datacache'
import * as challengeUtils from '../challengeUtils'
import * as security from '../insecurity'

let firstConnectedSocket: any = null

const globalWithSocketIO = global as typeof globalThis & {
  io: SocketIOClientStatic & Server
}

const MAX_TRACKED_CLIENTS = 1000
const acknowledgedNotifications = new Map<string, Set<string>>()

const tokenFromCookie = (cookieHeader?: string) => {
  const cookie = cookieHeader?.split(';').map(c => c.trim()).find(c => c.startsWith('token='))
  if (!cookie) return undefined
  try {
    return decodeURIComponent(cookie.substring('token='.length))
  } catch {
    return undefined
  }
}

const authenticatedUserOf = (handshake: any) => {
  const token = typeof handshake?.auth?.token === 'string' ? handshake.auth.token : tokenFromCookie(handshake?.headers?.cookie)
  if (!token || !security.verify(token)) return undefined
  return security.authenticatedUsers.get(token)?.data
}

const clientKeyOf = (socket: any) => {
  const clientId = socket.handshake?.auth?.clientId
  return typeof clientId === 'string' && /^[a-f0-9]{32}$/.test(clientId) ? `client:${clientId}` : `socket:${socket.id}`
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

    const user = authenticatedUserOf(socket.handshake)
    const clientKey = clientKeyOf(socket)

    const replayed = new Set<string>()
    notifications.forEach((notification: any) => {
      if (!acknowledgedNotifications.get(clientKey)?.has(notification.flag) && !replayed.has(notification.flag)) {
        replayed.add(notification.flag)
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
