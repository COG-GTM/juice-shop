/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

type PublicConfigSpec = true | PublicConfigSpec[] | { [key: string]: PublicConfigSpec }

const publicConfigSpec: PublicConfigSpec = {
  application: {
    domain: true,
    name: true,
    logo: true,
    favicon: true,
    theme: true,
    showVersionNumber: true,
    showGitHubLinks: true,
    localBackupEnabled: true,
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
    chatBot: {
      name: true,
      avatar: true,
      sampleQuestions: true
    },
    recyclePage: {
      topProductImage: true,
      bottomProductImage: true
    },
    welcomeBanner: {
      showOnFirstStart: true,
      title: true,
      message: true
    },
    cookieConsent: {
      message: true,
      dismissText: true,
      linkText: true,
      linkUrl: true
    },
    securityTxt: {
      contact: true,
      encryption: true,
      acknowledgements: true,
      hiring: true,
      csaf: true
    },
    promotion: {
      video: true,
      subtitles: true
    },
    googleOauth: {
      clientId: true,
      authorizedRedirects: [{ uri: true, proxy: true }]
    }
  },
  challenges: {
    showSolvedNotifications: true,
    showHints: true,
    showMitigations: true,
    codingChallengesEnabled: true,
    restrictToTutorialsFirst: true,
    safetyMode: true
  },
  hackingInstructor: {
    isEnabled: true,
    avatarImage: true,
    hintPlaybackSpeed: true
  },
  ctf: {
    showFlagsInNotifications: true,
    showCountryDetailsInNotifications: true,
    systemWideNotifications: {
      url: true,
      pollFrequencySeconds: true
    }
  }
}

const isPrimitive = (value: unknown) => value === null || typeof value !== 'object'

function pickPublic (value: any, spec: PublicConfigSpec): any {
  if (spec === true) {
    if (isPrimitive(value)) return value
    if (Array.isArray(value) && value.every(isPrimitive)) return [...value]
    return undefined
  }
  if (Array.isArray(spec)) {
    return Array.isArray(value) ? value.map((item) => pickPublic(item, spec[0])) : undefined
  }
  if (isPrimitive(value) || Array.isArray(value)) return undefined
  const result: Record<string, any> = {}
  for (const key of Object.keys(spec)) {
    if (value[key] === undefined) continue
    const picked = pickPublic(value[key], spec[key])
    if (picked !== undefined) result[key] = picked
  }
  return result
}

export function retrieveAppConfiguration () {
  return (_req: Request, res: Response) => {
    res.json({ config: pickPublic(config.util.toObject(config), publicConfigSpec) })
  }
}
