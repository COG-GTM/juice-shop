/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

const publicConfigKeys = [
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
  'application.chatBot.name',
  'application.chatBot.avatar',
  'application.chatBot.sampleQuestions',
  'application.social',
  'application.recyclePage',
  'application.welcomeBanner',
  'application.cookieConsent',
  'application.securityTxt',
  'application.promotion',
  'application.easterEggPlanet',
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
  'ctf.systemWideNotifications'
]

function setPath (target: Record<string, unknown>, path: string, value: unknown) {
  const segments = path.split('.')
  let current = target

  for (const segment of segments.slice(0, -1)) {
    if (typeof current[segment] !== 'object' || current[segment] === null || Array.isArray(current[segment])) {
      current[segment] = {}
    }
    current = current[segment] as Record<string, unknown>
  }

  current[segments[segments.length - 1]] = value
}

export function retrieveAppConfiguration () {
  return (_req: Request, res: Response) => {
    const publicConfig: Record<string, unknown> = {}
    for (const key of publicConfigKeys) {
      if (config.has(key)) {
        const value = config.get(key)
        const plainValue = value !== null && typeof value === 'object' ? config.util.toObject(value) : value
        setPath(publicConfig, key, structuredClone(plainValue))
      }
    }
    res.json({ config: publicConfig })
  }
}
