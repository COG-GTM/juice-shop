/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

const exposedConfigPaths = [
  'server.port',
  'application.domain',
  'application.name',
  'application.logo',
  'application.favicon',
  'application.theme',
  'application.showVersionNumber',
  'application.showGitHubLinks',
  'application.localBackupEnabled',
  'application.numberOfRandomFakeUsers',
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
  'application.cookieConsent.message',
  'application.cookieConsent.dismissText',
  'application.cookieConsent.linkText',
  'application.cookieConsent.linkUrl',
  'application.securityTxt.contact',
  'application.securityTxt.encryption',
  'application.securityTxt.acknowledgements',
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
  'challenges.overwriteUrlForProductTamperingChallenge',
  'hackingInstructor.isEnabled',
  'hackingInstructor.avatarImage',
  'hackingInstructor.hintPlaybackSpeed',
  'ctf.showFlagsInNotifications',
  'ctf.showCountryDetailsInNotifications',
  'ctf.countryMapping',
  'ctf.systemWideNotifications.url',
  'ctf.systemWideNotifications.pollFrequencySeconds'
]

function projectConfiguration (fullConfig: Record<string, any>) {
  const projection: Record<string, any> = {}
  for (const path of exposedConfigPaths) {
    const properties = path.split('.')
    const leaf = properties.pop() as string
    let source: Record<string, any> | undefined = fullConfig
    let target = projection
    for (const property of properties) {
      if (typeof source?.[property] !== 'object' || source[property] === null) {
        source = undefined
        break
      }
      source = source[property] as Record<string, any>
      target[property] ??= {}
      target = target[property]
    }
    if (source?.[leaf] !== undefined) {
      target[leaf] = source[leaf]
    }
  }
  return projection
}

export function retrieveAppConfiguration () {
  return (_req: Request, res: Response) => {
    const safeConfig = projectConfiguration(structuredClone(config.util.toObject(config)))
    res.json({ config: safeConfig })
  }
}
