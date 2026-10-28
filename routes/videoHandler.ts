/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import config from 'config'
import { type Request, type Response, type NextFunction } from 'express'
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
  return (req: Request, res: Response, next: NextFunction) => {
    fs.readFile('views/promotionVideo.pug', async function (err, buf) {
      if (err != null) throw err
      let template = buf.toString()
      let subs: string
      try {
        subs = getSubsFromFile()
      } catch (error) {
        next(error)
        return
      }

      challengeUtils.solveIf(challenges.videoXssChallenge, () => { return utils.contains(subs, '</script><script>alert(`xss`)</script>') })

      const themeKey = config.get<string>('application.theme') as keyof typeof themes
      const theme = themes[themeKey] || themes['bluegrey-lightgreen']
      template = template.replace(/_title_/g, entities.encode(config.get<string>('application.name')))
      template = template.replace(/_favicon_/g, favicon())
      template = template.replace(/_bgColor_/g, theme.bgColor)
      template = template.replace(/_textColor_/g, theme.textColor)
      template = template.replace(/_navColor_/g, theme.navColor)
      template = template.replace(/_primLight_/g, theme.primLight)
      template = template.replace(/_primDark_/g, theme.primDark)
      const pug = (await import('pug')).default
      const fn = pug.compile(template)
      let compiledTemplate = fn()
      const nonce = crypto.randomBytes(16).toString('base64')
      compiledTemplate = compiledTemplate.replace(/<script(?=[\s>])(?! id="subtitle")/g, `<script nonce="${nonce}"`)
      compiledTemplate = compiledTemplate.replace('<script id="subtitle"></script>', () => '<script id="subtitle" type="application/json" data-label="English" data-lang="en">' + serializeSubtitles(subs) + '</script>')
      res.set('Content-Security-Policy', promotionCsp(nonce))
      res.send(compiledTemplate)
    })
  }
  function favicon () {
    return utils.extractFilename(config.get('application.favicon'))
  }
}

export function promotionCsp (nonce: string) {
  return `script-src 'nonce-${nonce}' 'strict-dynamic'; object-src 'none'; base-uri 'none'`
}

export function serializeSubtitles (subs: string) {
  return JSON.stringify(subs).replace(/[<>&\u2028\u2029]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'))
}

function getSubsFromFile () {
  const configured = config.get<string>('application.promotion.subtitles') ?? 'owasp_promo.vtt'
  const subtitles = path.basename(utils.isUrl(configured) ? utils.extractFilename(configured) : configured)
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
