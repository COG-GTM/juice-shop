/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { Op } from 'sequelize'

import { ImageCaptchaModel } from '../models/imageCaptcha'
import * as security from '../lib/insecurity'

export function imageCaptchas () {
  return async (req: Request, res: Response) => {
    try {
      const { default: svgCaptcha } = await import('svg-captcha')
      const captcha = svgCaptcha.create({ size: 5, noise: 2, color: true })

      const user = security.authenticatedUsers.from(req)
      if (!user) {
        res.status(401).send(res.__('You need to be logged in to request a CAPTCHA.'))
        return
      }

      await ImageCaptchaModel.destroy({ where: { UserId: user.data.id } })
      const imageCaptchaInstance = ImageCaptchaModel.build({
        image: captcha.data,
        answer: captcha.text,
        UserId: user.data.id
      })
      await imageCaptchaInstance.save()
      res.json({
        image: captcha.data,
        UserId: user.data.id
      })
    } catch (error) {
      res.status(400).send(res.__('Unable to create CAPTCHA. Please try again.'))
    }
  }
}

export const verifyImageCaptcha = () => async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = security.authenticatedUsers.from(req)
    const UserId = user?.data?.id
    if (!UserId) {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
      return
    }
    const captcha = await ImageCaptchaModel.findOne({
      where: {
        UserId,
        createdAt: {
          [Op.gt]: new Date(Date.now() - 300000)
        }
      },
      order: [['createdAt', 'DESC']]
    })
    if (!captcha || req.body.answer !== captcha.answer) {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
      return
    }
    const consumed = await ImageCaptchaModel.destroy({ where: { id: captcha.id } })
    if (consumed !== 1) {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
      return
    }
    next()
  } catch (error) {
    res.status(401).send(res.__('Something went wrong while submitting CAPTCHA. Please try again.'))
  }
}
