/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { randomUUID } from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { Op } from 'sequelize'
import { CaptchaModel } from '../models/captcha'

export const CAPTCHA_TTL_MS = 5 * 60 * 1000

export function captchas () {
  return async (req: Request, res: Response) => {
    await CaptchaModel.destroy({ where: { createdAt: { [Op.lt]: new Date(Date.now() - CAPTCHA_TTL_MS) } } })
    const captchaId = randomUUID()
    const operators = ['*', '+', '-']

    const firstTerm = Math.floor((Math.random() * 10) + 1)
    const secondTerm = Math.floor((Math.random() * 10) + 1)
    const thirdTerm = Math.floor((Math.random() * 10) + 1)

    const firstOperator = operators[Math.floor((Math.random() * 3))]
    const secondOperator = operators[Math.floor((Math.random() * 3))]

    const expression = firstTerm.toString() + firstOperator + secondTerm.toString() + secondOperator + thirdTerm.toString()
    const answer = eval(expression).toString() // eslint-disable-line no-eval

    const captcha = {
      captchaId,
      captcha: expression,
      answer
    }
    const captchaInstance = CaptchaModel.build(captcha)
    await captchaInstance.save()
    res.json(captcha)
  }
}

export const verifyCaptcha = () => async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { captchaId } = req.body
    const captcha = typeof captchaId === 'string' ? await CaptchaModel.findOne({ where: { captchaId } }) : null
    // Every lookup consumes the captcha; only the request whose delete succeeds may use it
    const consumed = captcha != null && await CaptchaModel.destroy({ where: { captchaId } }) === 1
    const expired = captcha == null || Date.now() - captcha.createdAt.getTime() > CAPTCHA_TTL_MS
    if (consumed && !expired && req.body.captcha === captcha.answer) {
      next()
    } else {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
    }
  } catch (error) {
    next(error)
  }
}
