/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import config from 'config'
import { type NextFunction, type Request, type Response } from 'express'
import { AllHtmlEntities as Entities } from 'html-entities'

import * as challengeUtils from '../lib/challengeUtils'
import { themes } from '../views/themes/themes'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

const entities = new Entities()
const videosDir = 'frontend/dist/frontend/assets/public/videos/'

let pageShell: Promise<string> | undefined
let renderedPage: { subs: string, html: string } | undefined

export const getVideo = () => {
  return async (req: Request, res: Response, next: NextFunction) => {
    const path = videoPath()
    let fileSize: number
    try {
      fileSize = (await fs.promises.stat(path)).size
    } catch (err) {
      next(err)
      return
    }
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
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { subs, html } = await renderPromotionPage()
      challengeUtils.solveIf(challenges.videoXssChallenge, () => { return utils.contains(subs, '</script><script>alert(`xss`)</script>') })
      res.send(html)
    } catch (err) {
      next(err)
    }
  }
}

// Subtitles can be replaced at runtime (videoXssChallenge, custom subtitles download), so they are re-read on every request.
async function renderPromotionPage () {
  const subs = await fs.promises.readFile(subtitlesPath(), 'utf8')
  if (renderedPage?.subs === subs) {
    return renderedPage
  }
  const shell = await compilePageShell()
  const html = shell.replace('<script id="subtitle"></script>', '<script id="subtitle" type="text/vtt" data-label="English" data-lang="en">' + subs + '</script>')
  renderedPage = { subs, html }
  return renderedPage
}

async function compilePageShell () {
  pageShell ??= (async () => {
    let template = await fs.promises.readFile('views/promotionVideo.pug', 'utf8')
    const themeKey = config.get<string>('application.theme') as keyof typeof themes
    const theme = themes[themeKey] || themes['bluegrey-lightgreen']
    template = template.replace(/_title_/g, entities.encode(config.get<string>('application.name')))
    template = template.replace(/_favicon_/g, utils.extractFilename(config.get('application.favicon')))
    template = template.replace(/_bgColor_/g, theme.bgColor)
    template = template.replace(/_textColor_/g, theme.textColor)
    template = template.replace(/_navColor_/g, theme.navColor)
    template = template.replace(/_primLight_/g, theme.primLight)
    template = template.replace(/_primDark_/g, theme.primDark)
    const pug = (await import('pug')).default
    return pug.compile(template)()
  })()
  try {
    return await pageShell
  } catch (err) {
    pageShell = undefined
    throw err
  }
}

function subtitlesPath () {
  const subtitles = config.get<string>('application.promotion.subtitles') ?? 'owasp_promo.vtt'
  return videosDir + subtitles
}

function videoPath () {
  if (config.get<string>('application.promotion.video') !== null) {
    const video = utils.extractFilename(config.get<string>('application.promotion.video'))
    return videosDir + video
  }
  return videosDir + 'owasp_promo.mp4'
}
