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

const MAX_PAYLOAD_LENGTH = 10 * 1024
const svgInjectionPayload = /\.\.\/\.\.\/\.\.[\w/-]*?\/redirect\?to=https?:\/\/placecats.com\/(g\/)?[\d]+\/[\d]+/

const isBoundedString = (data: unknown): data is string => typeof data === 'string' && data.length <= MAX_PAYLOAD_LENGTH

const onSafely = (socket: any, event: string, handler: (data: unknown) => void) => {
  socket.on(event, (data: unknown) => {
    try {
      handler(data)
    } catch (error: unknown) {
      logger.warn(`Error handling websocket event "${event}": ${utils.getErrorMessage(error)}`)
    }
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

    notifications.forEach((notification: any) => {
      socket.emit('challenge solved', notification)
    })

    onSafely(socket, 'notification received', (data: unknown) => {
      if (!isBoundedString(data)) return
      const i = notifications.findIndex(({ flag }: any) => flag === data)
      if (i > -1) {
        notifications.splice(i, 1)
      }
    })

    onSafely(socket, 'verifyLocalXssChallenge', (data: unknown) => {
      if (!isBoundedString(data)) return
      challengeUtils.solveIf(challenges.localXssChallenge, () => { return utils.contains(data, '<iframe src="javascript:alert(`xss`)">') })
      challengeUtils.solveIf(challenges.xssBonusChallenge, () => { return utils.contains(data, config.get('challenges.xssBonusPayload')) })
    })

    onSafely(socket, 'verifySvgInjectionChallenge', (data: unknown) => {
      if (!isBoundedString(data)) return
      challengeUtils.solveIf(challenges.svgInjectionChallenge, () => { return svgInjectionPayload.test(data) && security.isRedirectAllowed(data) })
    })

    onSafely(socket, 'verifyCloseNotificationsChallenge', (data: unknown) => {
      challengeUtils.solveIf(challenges.closeNotificationsChallenge, () => { return Array.isArray(data) && data.length > 1 })
    })
  })
}

export default registerWebsocketEvents
