/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import os from 'node:os'
import config from 'config'
import colors from 'colors/safe'

import logger from './logger'
import * as utils from './utils'
import { totalCheatScore } from './antiCheat'

const loopbackHosts = ['localhost', '127.0.0.1', '::1', '[::1]']

const parseWebhookUrl = (webhook: string) => {
  try {
    return new URL(webhook)
  } catch {
    throw new Error(`Failed to parse URL from ${webhook}`)
  }
}

const assertEgressAllowed = (url: URL) => {
  if (url.protocol !== 'https:' && !loopbackHosts.includes(url.hostname)) {
    throw new Error(`Refusing to send solution data to non-HTTPS webhook host ${url.host}`)
  }
  const allowedHosts = (process.env.SOLUTIONS_WEBHOOK_ALLOWED_HOSTS ?? '').split(',').map((host) => host.trim()).filter((host) => host.length > 0)
  if (allowedHosts.length > 0 && !allowedHosts.includes(url.hostname)) {
    throw new Error(`Webhook host ${url.hostname} is not in SOLUTIONS_WEBHOOK_ALLOWED_HOSTS`)
  }
}

export const notify = async (challenge: { key: any, name: any }, cheatScore = -1, hintsAvailable = 0, hintsUnlocked = 0, webhook = process.env.SOLUTIONS_WEBHOOK) => {
  if (!webhook) {
    return
  }
  const url = parseWebhookUrl(webhook)
  assertEgressAllowed(url)
  const res = await fetch(webhook, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      solution: {
        challenge: challenge.key,
        hintsAvailable,
        hintsUnlocked,
        cheatScore,
        totalCheatScore: totalCheatScore(),
        issuedOn: new Date().toISOString()
      },
      ctfFlag: utils.ctfFlag(challenge.name),
      issuer: {
        hostName: os.hostname(),
        os: `${os.type()} (${os.release()})`,
        appName: config.get<string>('application.name'),
        config: process.env.NODE_ENV ?? 'default',
        version: utils.version()
      }
    })
  })
  logger.info(`Webhook ${colors.bold(url.origin)} notified about ${colors.cyan(challenge.key)} being solved: ${res.ok ? colors.green(res.status.toString()) : colors.red(res.status.toString())}`)
}
