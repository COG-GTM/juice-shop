/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

export const publicConfigKeys = [
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
  'application.social.blueSkyUrl',
  'application.social.mastodonUrl',
  'application.social.twitterUrl',
  'application.social.facebookUrl',
  'application.social.slackUrl',
  'application.social.redditUrl',
  'application.social.pressKitUrl',
  'application.social.nftUrl',
  'application.social.questionnaireUrl',
  'application.recyclePage.topProductImage',
  'application.recyclePage.bottomProductImage',
  'application.welcomeBanner.showOnFirstStart',
  'application.welcomeBanner.title',
  'application.welcomeBanner.message',
  'application.cookieConsent.message',
  'application.cookieConsent.dismissText',
  'application.cookieConsent.linkText',
  'application.cookieConsent.linkUrl',
  'application.securityTxt.contact',
  'application.securityTxt.encryption',
  'application.securityTxt.acknowledgements',
  'application.securityTxt.hiring',
  'application.securityTxt.csaf',
  'application.promotion.video',
  'application.promotion.subtitles',
  'application.easterEggPlanet.name',
  'application.easterEggPlanet.overlayMap',
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
        if (key === 'application.googleOauth.authorizedRedirects') {
          if (Array.isArray(value)) {
            const authorizedRedirects = value
              .filter((redirect): redirect is Record<string, unknown> => redirect !== null && typeof redirect === 'object' && !Array.isArray(redirect))
              .map(({ uri, proxy }) => ({
                uri,
                ...(proxy === undefined ? {} : { proxy })
              }))
            setPath(publicConfig, key, structuredClone(authorizedRedirects))
          }
          continue
        }

        if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
          continue
        }

        const plainValue = value !== null && typeof value === 'object' ? config.util.toObject(value) : value
        setPath(publicConfig, key, structuredClone(plainValue))
      }
    }
    res.json({ config: publicConfig })
  }
}
