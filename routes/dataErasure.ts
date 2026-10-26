/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import express, { type NextFunction, type Request, type Response } from 'express'
import path from 'node:path'
import crypto from 'node:crypto'
import config from 'config'
import { themes } from '../views/themes/themes'
import * as utils from '../lib/utils'
import { AllHtmlEntities as Entities } from 'html-entities'

import { SecurityQuestionModel } from '../models/securityQuestion'
import { PrivacyRequestModel } from '../models/privacyRequests'
import { SecurityAnswerModel } from '../models/securityAnswer'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'

const entities = new Entities()

const router = express.Router()

const csrfSecret = crypto.randomBytes(32)
const csrfTokenFor = (sessionToken: string) => crypto.createHmac('sha256', csrfSecret).update(sessionToken).digest('hex')

const safeEqual = (a: unknown, b: string) => {
  if (typeof a !== 'string') return false
  const left = Buffer.from(a)
  const right = Buffer.from(b)
  return left.length === right.length && crypto.timingSafeEqual(left, right)
}

router.get('/', (req: Request, res: Response, next: NextFunction) => {
  void (async () => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }
    const email = loggedInUser.data.email

    try {
      const answer = await SecurityAnswerModel.findOne({
        include: [{
          model: UserModel,
          where: { email }
        }]
      })
      if (answer == null) {
        throw new Error('No answer found!')
      }
      const question = await SecurityQuestionModel.findByPk(answer.SecurityQuestionId)
      if (question == null) {
        throw new Error('No question found!')
      }

      const themeKey = config.get<string>('application.theme') as keyof typeof themes
      const theme = themes[themeKey] || themes['bluegrey-lightgreen']
      res.render('dataErasureForm', {
        userEmail: email,
        csrfToken: csrfTokenFor(req.cookies.token),
        securityQuestion: question.question,
        _title_: entities.encode(config.get<string>('application.name')),
        _favicon_: utils.extractFilename(config.get('application.favicon')),
        _bgColor_: theme.bgColor,
        _textColor_: theme.textColor,
        _navColor_: theme.navColor,
        _primLight_: theme.primLight,
        _primDark_: theme.primDark,
        _logo_: utils.extractFilename(config.get('application.logo'))
      })
    } catch (error) {
      next(error)
    }
  })()
})

interface DataErasureRequestParams {
  layout?: string
  email: string
  securityAnswer: string
  _csrf: string
}

router.post('/', (req: Request<Record<string, unknown>, Record<string, unknown>, DataErasureRequestParams>, res: Response, next: NextFunction): void => {
  void (async () => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    if (!safeEqual(req.body._csrf, csrfTokenFor(req.cookies.token))) {
      res.status(403)
      next(new Error('Invalid or missing anti-forgery token'))
      return
    }

    try {
      const { email, securityAnswer } = req.body
      const answer = await SecurityAnswerModel.findOne({ where: { UserId: loggedInUser.data.id } })
      const emailConfirmed = typeof email === 'string' && email.trim().toLowerCase() === String(loggedInUser.data.email).toLowerCase()
      const answerConfirmed = answer != null && typeof securityAnswer === 'string' && safeEqual(security.hmac(securityAnswer), answer.answer)
      if (!emailConfirmed || !answerConfirmed) {
        res.status(403)
        next(new Error('Email address or security answer is incorrect'))
        return
      }

      await PrivacyRequestModel.create({
        UserId: loggedInUser.data.id,
        deletionRequested: true
      })

      res.clearCookie('token')

      const themeKey = config.get<string>('application.theme') as keyof typeof themes
      const theme = themes[themeKey] || themes['bluegrey-lightgreen']
      const themeVars = {
        _title_: entities.encode(config.get<string>('application.name')),
        _favicon_: utils.extractFilename(config.get('application.favicon')),
        _bgColor_: theme.bgColor,
        _textColor_: theme.textColor,
        _navColor_: theme.navColor,
        _primLight_: theme.primLight,
        _primDark_: theme.primDark,
        _logo_: utils.extractFilename(config.get('application.logo'))
      }

      if (req.body.layout) {
        const filePath: string = path.resolve(req.body.layout).toLowerCase()
        const isForbiddenFile: boolean = (filePath.includes('ftp') || filePath.includes('ctf.key') || filePath.includes('encryptionkeys'))
        if (!isForbiddenFile) {
          res.render('dataErasureResult', {
            ...req.body,
            ...themeVars
          }, (error, html) => {
            if (!html || error) {
              next(new Error(error.message))
            } else {
              const sendlfrResponse: string = html.slice(0, 100) + '......'
              res.send(sendlfrResponse)
              challengeUtils.solveIf(challenges.lfrChallenge, () => { return true })
            }
          })
        } else {
          next(new Error('File access not allowed'))
        }
      } else {
        res.render('dataErasureResult', {
          ...req.body,
          ...themeVars
        })
      }
    } catch (error) {
      next(error)
    }
  })()
})

export default router
