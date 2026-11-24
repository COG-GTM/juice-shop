/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as challengeUtils from '../lib/challengeUtils'
import { type Request, type Response } from 'express'

export function repeatNotification () {
  return ({ query }: Request, res: Response) => {
    const challengeName: string = decodeURIComponent(query.challenge as string)
    const challenge = challengeUtils.findChallengeByName(challengeName)
    const socketId = query.socketId

    if (challenge?.solved && typeof socketId === 'string' && socketId.length > 0) {
      challengeUtils.repeatNotification(challenge, socketId)
    }

    res.sendStatus(200)
  }
}
