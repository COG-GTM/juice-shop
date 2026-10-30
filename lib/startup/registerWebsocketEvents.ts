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
const verificationAttempts = new Map<string, Array<{ timestamp: number, payload: string }>>()

const hasValidSignature = (token: string) => {
  try {
    return security.verify(token)
  } catch {
    return false
  }
}

export const verifiedUserIdFrom = (token: unknown): number | undefined => {
  if (typeof token !== 'string' || token.length === 0 || !hasValidSignature(token)) {
    return undefined
  }
  const payload = security.decode(token) as { exp?: number, data?: { id?: unknown } } | undefined
  if (typeof payload?.exp === 'number' && payload.exp * 1000 < Date.now()) {
    return undefined
  }
  const id = payload?.data?.id
  return typeof id === 'number' ? id : undefined
}

const payloadFingerprint = (data: unknown) => {
  try {
    return JSON.stringify(data) ?? String(data)
  } catch {
    return String(data)
  }
}

const pruneExpiredVerificationAttempts = (now: number) => {
  for (const [key, attempts] of verificationAttempts) {
    if (attempts.every(({ timestamp }) => now - timestamp >= VERIFICATION_WINDOW_MS)) {
      verificationAttempts.delete(key)
    }
  }
}

export const isVerificationRateLimited = (key: string, data?: unknown, now = Date.now()) => {
  pruneExpiredVerificationAttempts(now)
  const recent = (verificationAttempts.get(key) ?? []).filter(({ timestamp }) => now - timestamp < VERIFICATION_WINDOW_MS)
  const payload = payloadFingerprint(data)
  if (recent.some((attempt) => attempt.payload === payload)) {
    verificationAttempts.set(key, recent)
    return false
  }
  recent.push({ timestamp: now, payload })
  verificationAttempts.set(key, recent)
  return recent.length > VERIFICATION_EVENT_LIMIT
}

export const verificationRateLimitEntryCount = () => verificationAttempts.size

export const resetVerificationRateLimits = () => { verificationAttempts.clear() }

const requiresAuthenticatedVerification = () => config.get<boolean>('ctf.showFlagsInNotifications')

const onChallengeVerification = (socket: any, event: string, verify: (data: any) => void) => {
  socket.on(event, (data: any, token?: unknown) => {
    const userId = verifiedUserIdFrom(token)
    if (userId === undefined && requiresAuthenticatedVerification()) {
      logger.info(`Ignored unauthenticated websocket event ${event} from socket ${socket.id}`)
      return
    }
    if (isVerificationRateLimited(userId !== undefined ? `user:${userId}` : `socket:${socket.id}`, [event, data])) {
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

export const replayPendingNotifications = (socket: any) => {
  if (requiresAuthenticatedVerification() && verifiedUserIdFrom(socket.handshake?.auth?.token) === undefined) {
    logger.info(`Withheld pending challenge notifications from unauthenticated socket ${socket.id}`)
    return
  }
  notifications.forEach((notification: any) => {
    socket.emit('challenge solved', notification)
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

    replayPendingNotifications(socket)
    registerNotificationAcknowledgement(socket)
    registerChallengeVerificationEvents(socket)
  })
}

export default registerWebsocketEvents
