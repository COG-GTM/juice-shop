/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'

import { challenges } from '../data/datacache'
import type { Product as ProductConfig } from './config.types'
import * as challengeUtils from './challengeUtils'
import logger from './logger'
import * as utils from './utils'

type TextCriteria = (text: string) => boolean

const containsAny = (...terms: string[]): TextCriteria => (text) => terms.some(term => text.includes(term.toLowerCase()))
const containsAll = (...terms: string[]): TextCriteria => (text) => terms.every(term => text.includes(term.toLowerCase()))

const textChallenges: Array<{ key: keyof typeof challenges, criteria: () => TextCriteria }> = [
  {
    key: 'knownVulnerableComponentChallenge',
    criteria: () => (text) => containsAll('sanitize-html', '1.4.2')(text) || containsAll('express-jwt', '0.1.3')(text)
  },
  { key: 'weirdCryptoChallenge', criteria: () => containsAny('z85', 'base85', 'hashids', 'md5', 'base64') },
  { key: 'typosquattingNpmChallenge', criteria: () => containsAny('epilogue-js') },
  { key: 'typosquattingAngularChallenge', criteria: () => containsAny('ngy-cookie') },
  { key: 'hiddenImageChallenge', criteria: () => containsAny('pickle rick') },
  { key: 'supplyChainAttackChallenge', criteria: () => containsAny('eslint-scope/issues/39', 'npm:eslint-scope:20180712') },
  { key: 'dlpPastebinDataLeakChallenge', criteria: () => containsAll(...dangerousIngredients()) },
  { key: 'csafChallenge', criteria: () => containsAny(config.get<string>('challenges.csafHashValue')) },
  { key: 'leakedApiKeyChallenge', criteria: () => containsAny('6PPi37DBxP4lDwlriuaxP15HaDJpsUXY5TspVmie') }
]

function dangerousIngredients (): string[] {
  return config.get<ProductConfig[]>('products')
    .flatMap((product) => product.keywordsForPastebinDataLeakChallenge ?? [])
    .filter(Boolean)
}

export function solveTextChallenges (text: unknown) {
  if (typeof text !== 'string' || text.length === 0) return
  const lowerCaseText = text.toLowerCase()
  for (const { key, criteria } of textChallenges) {
    const challenge = challenges[key]
    try {
      if (challengeUtils.notSolved(challenge) && criteria()(lowerCaseText)) {
        challengeUtils.solve(challenge)
      }
    } catch (error) {
      logger.warn(`Unable to verify challenge ${key}: ${utils.getErrorMessage(error)}`)
    }
  }
}

export async function solveFiveStarFeedbackChallenge (countFiveStarFeedback: () => Promise<number>) {
  if (!challengeUtils.notSolved(challenges.feedbackChallenge)) return
  try {
    if (await countFiveStarFeedback() === 0) {
      challengeUtils.solve(challenges.feedbackChallenge)
    }
  } catch (error) {
    logger.warn('Unable to retrieve feedback details: ' + utils.getErrorMessage(error))
  }
}
