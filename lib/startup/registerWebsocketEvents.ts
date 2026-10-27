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
import * as solverContext from '../solverContext'

let firstConnectedSocket: any = null

const globalWithSocketIO = global as typeof globalThis & {
  io: SocketIOClientStatic & Server
}

const MAX_TRACKED_VIEWERS = 1000
const acknowledgedNotifications = new Map<string, Set<string>>()

const handshakeToken = (handshake: any) => {
  const token = handshake?.auth?.token
  return typeof token === 'string' && token.length > 0 ? token : solverContext.tokenFromCookieHeader(handshake?.headers?.cookie)
}

const viewerKeyOf = (socket: any, userId?: number) => {
  if (userId !== undefined) return `user:${userId}`
  const clientId = socket.handshake?.auth?.clientId
  return typeof clientId === 'string' && /^[a-f0-9]{32}$/.test(clientId) ? `client:${clientId}` : `socket:${socket.id}`
}

const acknowledge = (viewerKey: string, notificationKey: string) => {
  let acknowledged = acknowledgedNotifications.get(viewerKey)
  if (!acknowledged) {
    if (acknowledgedNotifications.size >= MAX_TRACKED_VIEWERS) {
      acknowledgedNotifications.delete(acknowledgedNotifications.keys().next().value as string)
    }
    acknowledged = new Set<string>()
    acknowledgedNotifications.set(viewerKey, acknowledged)
  }
  acknowledged.add(notificationKey)
}

const registerWebsocketEvents = (server: any) => {
  const io = new Server(server, { cors: { origin: 'http://localhost:4200' } })
  // @ts-expect-error FIXME Type safety issue when setting global socket-io object
  globalWithSocketIO.io = io

  io.on('connection', (socket: any) => {
    const userId = solverContext.userIdFromToken(handshakeToken(socket.handshake))
    if (userId !== undefined) {
      solverContext.socketUserIds.set(socket, userId)
    }
    const viewerKey = viewerKeyOf(socket, userId)

    if (firstConnectedSocket === null) {
      socket.emit('server started')
      firstConnectedSocket = socket.id
    }

    notifications.forEach((notification) => {
      if (!acknowledgedNotifications.get(viewerKey)?.has(notification.key)) {
        socket.emit('challenge solved', challengeUtils.notificationFor(notification, userId))
      }
    })

    socket.on('notification received', (data: any) => {
      if (typeof data === 'string' && notifications.some(({ key }) => key === data)) {
        acknowledge(viewerKey, data)
      }
    })

    socket.on('disconnect', () => {
      if (viewerKey.startsWith('socket:')) {
        acknowledgedNotifications.delete(viewerKey)
      }
    })

    const onVerification = (event: string, verify: (data: any) => void) => {
      socket.on(event, (data: any) => {
        if (userId === undefined && config.get<boolean>('ctf.showFlagsInNotifications')) {
          return
        }
        solverContext.runAs(userId, () => { verify(data) })
      })
    }

    onVerification('verifyLocalXssChallenge', (data: any) => {
      challengeUtils.solveIf(challenges.localXssChallenge, () => { return utils.contains(data, '<iframe src="javascript:alert(`xss`)">') })
      challengeUtils.solveIf(challenges.xssBonusChallenge, () => { return utils.contains(data, config.get('challenges.xssBonusPayload')) })
    })

    onVerification('verifySvgInjectionChallenge', (data: any) => {
      challengeUtils.solveIf(challenges.svgInjectionChallenge, () => { return data?.match(/.*\.\.\/\.\.\/\.\.[\w/-]*?\/redirect\?to=https?:\/\/placecats.com\/(g\/)?[\d]+\/[\d]+.*/) && security.isRedirectAllowed(data) })
    })

    onVerification('verifyCloseNotificationsChallenge', (data: any) => {
      challengeUtils.solveIf(challenges.closeNotificationsChallenge, () => { return Array.isArray(data) && data.length > 1 })
    })
  })
}

export default registerWebsocketEvents
