/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { Op } from 'sequelize'
import jwt from 'jsonwebtoken'
import config from 'config'
import jws from 'jws'

import { products, challenges, retrieveBlueprintChallengeFile } from '../data/datacache'
import type { Product as ProductConfig } from '../lib/config.types'
import { type Challenge, type Product } from '../data/types'
import * as challengeUtils from '../lib/challengeUtils'
import { ComplaintModel } from '../models/complaint'
import { FeedbackModel } from '../models/feedback'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'
import { consumeChanges, markChanged, type TableChanges } from '../lib/tableChanges'

export const emptyUserRegistration = () => (req: Request, res: Response, next: NextFunction) => {
  challengeUtils.solveIf(challenges.emptyUserRegistration, () => {
    return req.body && req.body.email === '' && req.body.password === ''
  })
  next()
}

export const forgedFeedbackChallenge = () => (req: Request, res: Response, next: NextFunction) => {
  challengeUtils.solveIf(challenges.forgedFeedbackChallenge, () => {
    const user = security.authenticatedUsers.from(req)
    const userId = user?.data ? user.data.id : undefined
    return req.body?.UserId && req.body.UserId != userId // eslint-disable-line eqeqeq
  })
  next()
}

export const captchaBypassChallenge = () => (req: Request, res: Response, next: NextFunction) => {
  if (challengeUtils.notSolved(challenges.captchaBypassChallenge)) {
    if (req.app.locals.captchaReqId >= 10) {
      if ((new Date().getTime() - req.app.locals.captchaBypassReqTimes[req.app.locals.captchaReqId - 10]) <= 20000) {
        challengeUtils.solve(challenges.captchaBypassChallenge)
      }
    }
    req.app.locals.captchaBypassReqTimes[req.app.locals.captchaReqId - 1] = new Date().getTime()
    req.app.locals.captchaReqId++
  }
  next()
}

export const registerAdminChallenge = () => (req: Request, res: Response, next: NextFunction) => {
  challengeUtils.solveIf(challenges.registerAdminChallenge, () => {
    return req.body && req.body.role === security.roles.admin
  })
  next()
}

export const passwordRepeatChallenge = () => (req: Request, res: Response, next: NextFunction) => {
  challengeUtils.solveIf(challenges.passwordRepeatChallenge, () => { return req.body && req.body.passwordRepeat !== req.body.password })
  next()
}

export const accessControlChallenges = () => (req: Request, res: Response, next: NextFunction) => {
  const { url } = req
  const uiBypassed = req.header('sec-fetch-dest') === 'document' || !req.header('referer')
  challengeUtils.solveIf(challenges.scoreBoardChallenge, () => { return utils.endsWith(url, '/1px.png') }, false, uiBypassed)
  challengeUtils.solveIf(challenges.web3SandboxChallenge, () => { return utils.endsWith(url, '/11px.png') }, false, uiBypassed)
  challengeUtils.solveIf(challenges.adminSectionChallenge, () => { return utils.endsWith(url, '/19px.png') }, false, uiBypassed)
  challengeUtils.solveIf(challenges.tokenSaleChallenge, () => { return utils.endsWith(url, '/56px.png') }, false, uiBypassed)
  challengeUtils.solveIf(challenges.privacyPolicyChallenge, () => { return utils.endsWith(url, '/81px.png') }, false, uiBypassed)
  challengeUtils.solveIf(challenges.extraLanguageChallenge, () => { return utils.endsWith(url, '/tlh_AA.json') })
  challengeUtils.solveIf(challenges.retrieveBlueprintChallenge, () => { return utils.endsWith(url, retrieveBlueprintChallengeFile ?? undefined) })
  challengeUtils.solveIf(challenges.securityPolicyChallenge, () => { return utils.endsWith(url, '/security.txt') })
  challengeUtils.solveIf(challenges.missingEncodingChallenge, () => { return utils.endsWith(url.toLowerCase(), '%e1%93%9a%e1%98%8f%e1%97%a2-%23zatschi-%23whoneedsfourlegs-1572600969477.jpg') })
  challengeUtils.solveIf(challenges.accessLogDisclosureChallenge, () => { return url.match(/access\.log(0-9-)*/) })
  next()
}

export const errorHandlingChallenge = () => (err: unknown, req: Request, { statusCode }: Response, next: NextFunction) => {
  challengeUtils.solveIf(challenges.errorHandlingChallenge, () => { return err && (statusCode === 200 || statusCode > 401) })
  next(err)
}

export const jwtChallenges = () => (req: Request, res: Response, next: NextFunction) => {
  if (challengeUtils.notSolved(challenges.jwtUnsignedChallenge)) {
    jwtChallenge(challenges.jwtUnsignedChallenge, req, 'none', /jwtn3d@/)
  }
  if (utils.isChallengeEnabled(challenges.jwtForgedChallenge) && challengeUtils.notSolved(challenges.jwtForgedChallenge)) {
    jwtChallenge(challenges.jwtForgedChallenge, req, 'HS256', /rsa_lord@/)
  }
  next()
}

export const serverSideChallenges = () => (req: Request, res: Response, next: NextFunction) => {
  if (req.query.key === 'tRy_H4rd3r_n0thIng_iS_Imp0ssibl3') {
    if (challengeUtils.notSolved(challenges.sstiChallenge) && req.app.locals.abused_ssti_bug === true) {
      challengeUtils.solve(challenges.sstiChallenge)
      res.status(204).send()
      return
    }

    if (challengeUtils.notSolved(challenges.ssrfChallenge) && req.app.locals.abused_ssrf_bug === true) {
      challengeUtils.solve(challenges.ssrfChallenge)
      res.status(204).send()
      return
    }
  }
  next()
}

function jwtChallenge (challenge: Challenge, req: Request, algorithm: string, email: string | RegExp) {
  const token = utils.jwtFrom(req)
  if (token) {
    const decoded = jws.decode(token) ? jwt.decode(token) : null

    if (decoded === null || typeof decoded === 'string') {
      return
    }

    jwt.verify(token, security.publicKey, (err: jwt.VerifyErrors | null) => {
      if (err === null) {
        challengeUtils.solveIf(challenge, () => {
          return hasAlgorithm(token, algorithm) && hasEmail(decoded as { data: { email: string } }, email)
        })
      }
    })
  }
}

function hasAlgorithm (token: string, algorithm: string) {
  const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64').toString())
  return token && header && header.alg === algorithm
}

function hasEmail (token: { data: { email: string } }, email: string | RegExp) {
  return token?.data?.email?.match(email)
}

async function checkPatternInFeedbackAndComplaints (
  challenge: Challenge,
  fieldCriteria: any,
  changes: TableChanges
): Promise<void> {
  const checks: Array<Promise<void>> = []
  if (changes.Feedbacks) {
    checks.push(FeedbackModel.count({
      where: { comment: fieldCriteria }
    }).then((count: number) => {
      if (count > 0) {
        challengeUtils.solve(challenge)
      }
    }).catch(() => {
      markChanged('Feedbacks')
      throw new Error('Unable to retrieve feedback details. Please try again')
    }))
  }
  if (changes.Complaints) {
    checks.push(ComplaintModel.count({
      where: { message: fieldCriteria }
    }).then((count: number) => {
      if (count > 0) {
        challengeUtils.solve(challenge)
      }
    }).catch(() => {
      markChanged('Complaints')
      throw new Error('Unable to retrieve complaint details. Please try again')
    }))
  }

  await Promise.all(checks)
}

/* Solve state only changes when Feedbacks, Complaints or Products are written, so checks run once after such a write */
export const databaseRelatedChallenges = () => (req: Request, res: Response, next: NextFunction) => {
  const changes = consumeChanges()
  if (changes.Products && challengeUtils.notSolved(challenges.changeProductChallenge) && products.osaft) {
    changeProductChallenge(products.osaft)
  }
  if (changes.Feedbacks && challengeUtils.notSolved(challenges.feedbackChallenge)) {
    feedbackChallenge()
  }
  if (!changes.Feedbacks && !changes.Complaints) {
    next()
    return
  }
  if (challengeUtils.notSolved(challenges.knownVulnerableComponentChallenge)) {
    knownVulnerableComponentChallenge(changes)
  }
  if (challengeUtils.notSolved(challenges.weirdCryptoChallenge)) {
    weirdCryptoChallenge(changes)
  }
  if (challengeUtils.notSolved(challenges.typosquattingNpmChallenge)) {
    typosquattingNpmChallenge(changes)
  }
  if (challengeUtils.notSolved(challenges.typosquattingAngularChallenge)) {
    typosquattingAngularChallenge(changes)
  }
  if (challengeUtils.notSolved(challenges.hiddenImageChallenge)) {
    hiddenImageChallenge(changes)
  }
  if (challengeUtils.notSolved(challenges.supplyChainAttackChallenge)) {
    supplyChainAttackChallenge(changes)
  }
  if (challengeUtils.notSolved(challenges.dlpPastebinDataLeakChallenge)) {
    dlpPastebinDataLeakChallenge(changes)
  }
  if (challengeUtils.notSolved(challenges.csafChallenge)) {
    csafChallenge(changes)
  }
  if (challengeUtils.notSolved(challenges.leakedApiKeyChallenge)) {
    leakedApiKeyChallenge(changes)
  }
  next()
}

function changeProductChallenge (osaft: Product) {
  let urlForProductTamperingChallenge: string | null = null
  void osaft.reload().then(() => {
    for (const product of config.get<ProductConfig[]>('products')) {
      if (product.urlForProductTamperingChallenge !== undefined) {
        urlForProductTamperingChallenge = product.urlForProductTamperingChallenge
        break
      }
    }
    if (urlForProductTamperingChallenge) {
      if (!utils.contains(osaft.description, `${urlForProductTamperingChallenge}`)) {
        if (utils.contains(osaft.description, `<a href="${config.get<string>('challenges.overwriteUrlForProductTamperingChallenge')}" target="_blank">`)) {
          challengeUtils.solve(challenges.changeProductChallenge)
        }
      }
    }
  }, () => {
    markChanged('Products')
  })
}

function feedbackChallenge () {
  FeedbackModel.count({ where: { rating: 5 } }).then((count: number) => {
    if (count === 0) {
      challengeUtils.solve(challenges.feedbackChallenge)
    }
  }).catch(() => {
    markChanged('Feedbacks')
    throw new Error('Unable to retrieve feedback details. Please try again')
  })
}

function knownVulnerableComponentChallenge (changes: TableChanges) {
  void checkPatternInFeedbackAndComplaints(
    challenges.knownVulnerableComponentChallenge,
    { [Op.or]: knownVulnerableComponents() },
    changes
  )
}

function knownVulnerableComponents () {
  return [
    {
      [Op.and]: [
        { [Op.like]: '%sanitize-html%' },
        { [Op.like]: '%1.4.2%' }
      ]
    },
    {
      [Op.and]: [
        { [Op.like]: '%express-jwt%' },
        { [Op.like]: '%0.1.3%' }
      ]
    }
  ]
}

function weirdCryptoChallenge (changes: TableChanges) {
  void checkPatternInFeedbackAndComplaints(
    challenges.weirdCryptoChallenge,
    { [Op.or]: weirdCryptos() },
    changes
  )
}

function weirdCryptos () {
  return [
    { [Op.like]: '%z85%' },
    { [Op.like]: '%base85%' },
    { [Op.like]: '%hashids%' },
    { [Op.like]: '%md5%' },
    { [Op.like]: '%base64%' }
  ]
}

function typosquattingNpmChallenge (changes: TableChanges) {
  void checkPatternInFeedbackAndComplaints(
    challenges.typosquattingNpmChallenge,
    { [Op.like]: '%epilogue-js%' },
    changes
  )
}

function typosquattingAngularChallenge (changes: TableChanges) {
  void checkPatternInFeedbackAndComplaints(
    challenges.typosquattingAngularChallenge,
    { [Op.like]: '%ngy-cookie%' },
    changes
  )
}

function hiddenImageChallenge (changes: TableChanges) {
  void checkPatternInFeedbackAndComplaints(
    challenges.hiddenImageChallenge,
    { [Op.like]: '%pickle rick%' },
    changes
  )
}

function supplyChainAttackChallenge (changes: TableChanges) {
  void checkPatternInFeedbackAndComplaints(
    challenges.supplyChainAttackChallenge,
    { [Op.or]: eslintScopeVulnIds() },
    changes
  )
}

function eslintScopeVulnIds () {
  return [
    { [Op.like]: '%eslint-scope/issues/39%' },
    { [Op.like]: '%npm:eslint-scope:20180712%' }
  ]
}

function dlpPastebinDataLeakChallenge (changes: TableChanges) {
  void checkPatternInFeedbackAndComplaints(
    challenges.dlpPastebinDataLeakChallenge,
    { [Op.and]: dangerousIngredients() },
    changes
  )
}

function csafChallenge (changes: TableChanges) {
  void checkPatternInFeedbackAndComplaints(
    challenges.csafChallenge,
    { [Op.like]: '%' + config.get<string>('challenges.csafHashValue') + '%' },
    changes
  )
}

function leakedApiKeyChallenge (changes: TableChanges) {
  void checkPatternInFeedbackAndComplaints(
    challenges.leakedApiKeyChallenge,
    { [Op.like]: '%6PPi37DBxP4lDwlriuaxP15HaDJpsUXY5TspVmie%' },
    changes
  )
}

function dangerousIngredients () {
  return config.get<ProductConfig[]>('products')
    .flatMap((product) => product.keywordsForPastebinDataLeakChallenge)
    .filter(Boolean)
    .map((keyword) => {
      return { [Op.like]: `%${keyword}%` }
    })
}
