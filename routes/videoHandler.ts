/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import config from 'config'
import pug from 'pug'
import { type Request, type Response } from 'express'
import { AllHtmlEntities as Entities } from 'html-entities'

import * as challengeUtils from '../lib/challengeUtils'
import { themes } from '../views/themes/themes'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

const entities = new Entities()

export const getVideo = () => {
  return (req: Request, res: Response) => {
    const path = videoPath()
    const stat = fs.statSync(path)
    const fileSize = stat.size
    const range = req.headers.range
    if (range) {
      const parts = range.replace(/bytes=/, '').split('-')
      const start = parseInt(parts[0], 10)
      const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1
      const chunksize = (end - start) + 1
      const file = fs.createReadStream(path, { start, end })
      const head = {
        'Content-Range': `bytes ${start}-${end}/${fileSize}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunksize,
        'Content-Location': '/assets/public/videos/owasp_promo.mp4',
        'Content-Type': 'video/mp4'
      }
      res.writeHead(206, head)
      file.pipe(res)
    } else {
      const head = {
        'Content-Length': fileSize,
        'Content-Type': 'video/mp4'
      }
      res.writeHead(200, head)
      fs.createReadStream(path).pipe(res)
    }
  }
}

export const promotionVideo = () => {
  const compiledTemplate = compilePromotionTemplate()
  return (req: Request, res: Response) => {
    const subs = getSubsFromFile()

    challengeUtils.solveIf(challenges.videoXssChallenge, () => { return utils.contains(subs, '</script><script>alert(`xss`)</script>') })

    res.send(compiledTemplate.replace('<script id="subtitle"></script>', '<script id="subtitle" type="application/json" data-label="English" data-lang="en">' + serializeForScript(subs) + '</script>'))
  }
}

function compilePromotionTemplate () {
  let template = fs.readFileSync('views/promotionVideo.pug', 'utf8')
  const themeKey = config.get<string>('application.theme') as keyof typeof themes
  const theme = themes[themeKey] || themes['bluegrey-lightgreen']
  template = template.replace(/_title_/g, entities.encode(config.get<string>('application.name')))
  template = template.replace(/_favicon_/g, utils.extractFilename(config.get('application.favicon')))
  template = template.replace(/_bgColor_/g, theme.bgColor)
  template = template.replace(/_textColor_/g, theme.textColor)
  template = template.replace(/_navColor_/g, theme.navColor)
  template = template.replace(/_primLight_/g, theme.primLight)
  template = template.replace(/_primDark_/g, theme.primDark)
  return pug.compile(template)()
}

function serializeForScript (value: string) {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029')
}

function getSubsFromFile () {
  const subtitles = config.get<string>('application.promotion.subtitles') ?? 'owasp_promo.vtt'
  const data = fs.readFileSync('frontend/dist/frontend/assets/public/videos/' + subtitles, 'utf8')
  return data.toString()
}

function videoPath () {
  if (config.get<string>('application.promotion.video') !== null) {
    const video = utils.extractFilename(config.get<string>('application.promotion.video'))
    return 'frontend/dist/frontend/assets/public/videos/' + video
  }
  return 'frontend/dist/frontend/assets/public/videos/owasp_promo.mp4'
}
