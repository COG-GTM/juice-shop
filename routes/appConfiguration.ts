/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

interface AllowlistShape { [key: string]: true | AllowlistShape }

// Settings the frontend reads (see Config in frontend/src/app/Services/configuration.service.ts and frontend/src/hacking-instructor)
export const publicConfigAllowlist: AllowlistShape = {
  server: { port: true },
  application: {
    domain: true,
    name: true,
    logo: true,
    favicon: true,
    theme: true,
    showVersionNumber: true,
    showGitHubLinks: true,
    localBackupEnabled: true,
    numberOfRandomFakeUsers: true,
    altcoinName: true,
    privacyContactEmail: true,
    social: {
      blueSkyUrl: true,
      mastodonUrl: true,
      twitterUrl: true,
      facebookUrl: true,
      slackUrl: true,
      redditUrl: true,
      pressKitUrl: true,
      nftUrl: true,
      questionnaireUrl: true
    },
    chatBot: { name: true, avatar: true, sampleQuestions: true },
    recyclePage: { topProductImage: true, bottomProductImage: true },
    welcomeBanner: { showOnFirstStart: true, title: true, message: true },
    cookieConsent: { message: true, dismissText: true, linkText: true, linkUrl: true },
    securityTxt: { contact: true, encryption: true, acknowledgements: true },
    promotion: { video: true, subtitles: true },
    easterEggPlanet: { name: true, overlayMap: true },
    googleOauth: { clientId: true, authorizedRedirects: true }
  },
  challenges: {
    showSolvedNotifications: true,
    showHints: true,
    showMitigations: true,
    codingChallengesEnabled: true,
    restrictToTutorialsFirst: true,
    safetyMode: true,
    overwriteUrlForProductTamperingChallenge: true
  },
  hackingInstructor: { isEnabled: true, avatarImage: true, hintPlaybackSpeed: true },
  ctf: {
    showFlagsInNotifications: true,
    showCountryDetailsInNotifications: true,
    countryMapping: true,
    systemWideNotifications: { url: true, pollFrequencySeconds: true }
  }
}

function pickAllowlisted (source: Record<string, any>, allowlist: AllowlistShape) {
  const result: Record<string, any> = {}
  for (const [key, rule] of Object.entries(allowlist)) {
    if (source[key] === undefined) continue
    if (rule === true) {
      result[key] = source[key]
    } else if (typeof source[key] === 'object' && source[key] !== null) {
      result[key] = pickAllowlisted(source[key], rule)
    }
  }
  return result
}

export function retrieveAppConfiguration () {
  return (_req: Request, res: Response) => {
    const safeConfig = pickAllowlisted(structuredClone(config.util.toObject(config)), publicConfigAllowlist)
    res.json({ config: safeConfig })
  }
}
