/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

const publicConfigPaths = [
  'application.domain',
  'application.name',
  'application.logo',
  'application.favicon',
  'application.theme',
  'application.showVersionNumber',
  'application.showGitHubLinks',
  'application.localBackupEnabled',
  'application.altcoinName',
  'application.privacyContactEmail',
  'application.social',
  'application.chatBot.name',
  'application.chatBot.avatar',
  'application.chatBot.sampleQuestions',
  'application.recyclePage',
  'application.welcomeBanner',
  'application.cookieConsent',
  'application.securityTxt',
  'application.promotion',
  'application.googleOauth.clientId',
  'application.googleOauth.authorizedRedirects',
  'challenges.showSolvedNotifications',
  'challenges.showHints',
  'challenges.showMitigations',
  'challenges.codingChallengesEnabled',
  'challenges.restrictToTutorialsFirst',
  'challenges.safetyMode',
  'hackingInstructor.isEnabled',
  'hackingInstructor.avatarImage',
  'hackingInstructor.hintPlaybackSpeed',
  'ctf.showFlagsInNotifications',
  'ctf.showCountryDetailsInNotifications',
  'ctf.systemWideNotifications.url',
  'ctf.systemWideNotifications.pollFrequencySeconds'
]

function buildPublicConfig () {
  const publicConfig: Record<string, any> = {}
  for (const path of publicConfigPaths) {
    if (!config.has(path)) continue
    const keys = path.split('.')
    const leaf = keys.pop() as string
    let target = publicConfig
    for (const key of keys) {
      target[key] ??= {}
      target = target[key]
    }
    const value = config.get(path)
    target[leaf] = value !== null && typeof value === 'object' ? structuredClone(config.util.toObject(value)) : value
  }
  return publicConfig
}

export function retrieveAppConfiguration () {
  return (_req: Request, res: Response) => {
    res.json({ config: buildPublicConfig() })
  }
}
