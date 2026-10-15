/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

export const clientConfigurationAllowlist = [
  'application.domain',
  'application.name',
  'application.logo',
  'application.theme',
  'application.showGitHubLinks',
  'application.altcoinName',
  'application.privacyContactEmail',
  'application.social.blueSkyUrl',
  'application.social.mastodonUrl',
  'application.social.twitterUrl',
  'application.social.facebookUrl',
  'application.social.slackUrl',
  'application.social.redditUrl',
  'application.social.pressKitUrl',
  'application.social.nftUrl',
  'application.social.questionnaireUrl',
  'application.chatBot.name',
  'application.chatBot.avatar',
  'application.chatBot.sampleQuestions',
  'application.recyclePage.topProductImage',
  'application.recyclePage.bottomProductImage',
  'application.welcomeBanner.showOnFirstStart',
  'application.welcomeBanner.title',
  'application.welcomeBanner.message',
  'application.googleOauth.clientId',
  'application.googleOauth.authorizedRedirects',
  'challenges.codingChallengesEnabled',
  'challenges.restrictToTutorialsFirst',
  'hackingInstructor.isEnabled',
  'hackingInstructor.hintPlaybackSpeed',
  'ctf.showFlagsInNotifications',
  'ctf.showCountryDetailsInNotifications',
  'ctf.systemWideNotifications.url',
  'ctf.systemWideNotifications.pollFrequencySeconds'
]

function buildClientConfiguration () {
  const clientConfig: Record<string, any> = {}
  for (const path of clientConfigurationAllowlist) {
    if (!config.has(path)) continue
    const keys = path.split('.')
    const leaf = keys.pop() as string
    let target = clientConfig
    for (const key of keys) {
      target[key] ??= {}
      target = target[key]
    }
    target[leaf] = structuredClone(config.get(path))
  }
  return clientConfig
}

export function retrieveAppConfiguration () {
  return (_req: Request, res: Response) => {
    res.json({ config: buildClientConfiguration() })
  }
}
