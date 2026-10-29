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
import logger from '../logger'

let firstConnectedSocket: any = null

const globalWithSocketIO = global as typeof globalThis & {
  io: SocketIOClientStatic & Server
}

export const VERIFICATION_EVENT_LIMIT = 20
export const VERIFICATION_WINDOW_MS = 60 * 1000
const verificationAttempts = new Map<string, number[]>()

const hasValidSignature = (token: string) => {
  try {
    return security.verify(token)
  } catch {
    return false
  }
}

export const verifiedSessionFrom = (token: unknown): { userId: number, expiresAt: number } | undefined => {
  if (typeof token !== 'string' || token.length === 0 || !hasValidSignature(token)) {
    return undefined
  }
  const payload = security.decode(token) as { exp?: number, data?: { id?: unknown } } | undefined
  const expiresAt = typeof payload?.exp === 'number' ? payload.exp * 1000 : Number.POSITIVE_INFINITY
  if (expiresAt < Date.now()) {
    return undefined
  }
  const id = payload?.data?.id
  return typeof id === 'number' ? { userId: id, expiresAt } : undefined
}

export const verifiedUserIdFrom = (token: unknown): number | undefined => verifiedSessionFrom(token)?.userId

export const authenticateSocket = (socket: any, token: unknown) => {
  const session = verifiedSessionFrom(token)
  if (session === undefined) {
    challengeUtils.revokeFlagAccess(socket)
    return false
  }
  const hadFlagAccess = challengeUtils.canReceiveFlags(socket)
  challengeUtils.grantFlagAccess(socket, session.expiresAt)
  return !hadFlagAccess
}

const emitPendingNotifications = (socket: any) => {
  notifications.forEach((notification: any) => {
    socket.emit('challenge solved', challengeUtils.notificationFor(socket, notification))
  })
}

export const registerSocketAuthentication = (socket: any) => {
  authenticateSocket(socket, socket.handshake?.auth?.token)
  socket.on('authenticate', (token: unknown) => {
    if (authenticateSocket(socket, token) && requiresAuthenticatedVerification()) {
      emitPendingNotifications(socket)
    }
  })
}

export const isVerificationRateLimited = (key: string, now = Date.now()) => {
  const recent = (verificationAttempts.get(key) ?? []).filter((timestamp) => now - timestamp < VERIFICATION_WINDOW_MS)
  recent.push(now)
  verificationAttempts.set(key, recent)
  return recent.length > VERIFICATION_EVENT_LIMIT
}

export const resetVerificationRateLimits = () => { verificationAttempts.clear() }

const requiresAuthenticatedVerification = () => config.get<boolean>('ctf.showFlagsInNotifications')

const onChallengeVerification = (socket: any, event: string, verify: (data: any) => void) => {
  socket.on(event, (data: any, token?: unknown) => {
    const userId = verifiedUserIdFrom(token)
    if (userId === undefined && requiresAuthenticatedVerification()) {
      logger.info(`Ignored unauthenticated websocket event ${event} from socket ${socket.id}`)
      return
    }
    if (isVerificationRateLimited(userId !== undefined ? `user:${userId}` : `socket:${socket.id}`)) {
      logger.info(`Rate-limited websocket event ${event} from ${userId !== undefined ? `user ${userId}` : `socket ${socket.id}`}`)
      return
    }
    verify(data)
  })
}

export const registerNotificationAcknowledgement = (socket: any) => {
  socket.on('notification received', (data: any, token?: unknown) => {
    if (requiresAuthenticatedVerification() && verifiedUserIdFrom(token) === undefined) {
      logger.info(`Ignored unauthenticated notification acknowledgement from socket ${socket.id}`)
      return
    }
    if (typeof data !== 'string') {
      return
    }
    const i = notifications.findIndex(({ flag }: any) => flag === data)
    if (i > -1) {
      notifications.splice(i, 1)
    }
  })
}

export const registerChallengeVerificationEvents = (socket: any) => {
  onChallengeVerification(socket, 'verifyLocalXssChallenge', (data: any) => {
    challengeUtils.solveIf(challenges.localXssChallenge, () => { return utils.contains(data, '<iframe src="javascript:alert(`xss`)">') })
    challengeUtils.solveIf(challenges.xssBonusChallenge, () => { return utils.contains(data, config.get('challenges.xssBonusPayload')) })
  })

  onChallengeVerification(socket, 'verifySvgInjectionChallenge', (data: any) => {
    challengeUtils.solveIf(challenges.svgInjectionChallenge, () => { return data?.match(/.*\.\.\/\.\.\/\.\.[\w/-]*?\/redirect\?to=https?:\/\/placecats.com\/(g\/)?[\d]+\/[\d]+.*/) && security.isRedirectAllowed(data) })
  })

  onChallengeVerification(socket, 'verifyCloseNotificationsChallenge', (data: any) => {
    challengeUtils.solveIf(challenges.closeNotificationsChallenge, () => { return Array.isArray(data) && data.length > 1 })
  })

  socket.on('disconnect', () => {
    verificationAttempts.delete(`socket:${socket.id}`)
  })
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

    registerSocketAuthentication(socket)
    emitPendingNotifications(socket)

    registerNotificationAcknowledgement(socket)
    registerChallengeVerificationEvents(socket)
  })
}

export default registerWebsocketEvents
