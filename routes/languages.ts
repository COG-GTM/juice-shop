/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import locales from '../data/static/locales.json'
import { readFile, readdir, stat } from 'node:fs/promises'
import { type Request, type Response, type NextFunction } from 'express'
import logger from '../lib/logger'
import * as utils from '../lib/utils'

interface Language { key: string, lang: any, icons: string[], shortKey: string, percentage: number, gauge: string }

const frontendI18nDir = 'frontend/dist/frontend/assets/i18n/'
const backendI18nDir = 'i18n/'

export function getLanguageList () {
  let cached: { signature: string, languages: Promise<Language[]> } | null = null

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const signature = await i18nSignature()
      if (cached?.signature !== signature) {
        const languages = buildLanguageList()
        cached = { signature, languages }
        languages.catch(() => {
          if (cached?.languages === languages) cached = null
        })
      }
      const languages = cached.languages
      res.status(200).json(await languages)
    } catch (err: any) {
      next(err)
    }
  }

  async function i18nSignature (): Promise<string> {
    const dirSignatures = await Promise.all([frontendI18nDir, backendI18nDir].map(async (dir) => {
      let dirMtimeMs: number
      let fileNames: string[]
      try {
        dirMtimeMs = (await stat(dir)).mtimeMs
        fileNames = (await readdir(dir)).sort()
      } catch {
        return dir + '?'
      }
      const fileSignatures = await Promise.all(fileNames.map(async (fileName) => {
        try {
          const { mtimeMs, size } = await stat(dir + fileName)
          return `${fileName}@${mtimeMs}/${size}`
        } catch {
          return fileName + '?'
        }
      }))
      return `${dir}@${dirMtimeMs}|` + fileSignatures.join('|')
    }))
    return dirSignatures.join('\n')
  }

  async function buildLanguageList (): Promise<Language[]> {
    const languages: Language[] = []

    const enContentStr = await readFile(frontendI18nDir + 'en.json', 'utf-8')
    const enContent = JSON.parse(enContentStr)

    let backendEnContent: any = null
    try {
      const backendEnContentStr = await readFile(backendI18nDir + 'en.json', 'utf-8')
      backendEnContent = JSON.parse(backendEnContentStr)
    } catch (e: unknown) {
      logger.warn('Backend translations not available, will use frontend-only percentages: ' + utils.getErrorMessage(e))
    }

    const languageFiles = await readdir(frontendI18nDir)

    const languagePromises = languageFiles.map(async (fileName) => {
      const content = await readFile(frontendI18nDir + fileName, 'utf-8')
      const fileContent = JSON.parse(content)
      const frontendPercentage = calcPercentage(fileContent, enContent)
      const key = fileName.substring(0, fileName.indexOf('.'))
      const locale = locales.find((l) => l.key === key)

      let backendPercentage = 0
      if (backendEnContent !== null) {
        try {
          const backendContent = await readFile(backendI18nDir + fileName, 'utf-8')
          const backendFileContent = JSON.parse(backendContent)
          backendPercentage = calcPercentage(backendFileContent, backendEnContent)
        } catch {
          backendPercentage = 0
        }
      }

      const percentage = Math.round(backendEnContent !== null ? (frontendPercentage + backendPercentage) / 2 : frontendPercentage)
      const gauge = (percentage > 80 ? 'full' : (percentage > 60 ? 'three-quarters' : (percentage > 40 ? 'half' : (percentage > 20 ? 'quarter' : 'empty'))))

      const lang: any = {
        key,
        lang: fileContent.LANGUAGE,
        icons: locale?.icons,
        shortKey: locale?.shortKey,
        percentage,
        gauge
      }
      if (!(fileName === 'en.json' || fileName === 'tlh_AA.json')) {
        return lang
      }
      return null
    })

    const results = await Promise.all(languagePromises)
    results.forEach((lang) => {
      if (lang !== null) {
        languages.push(lang)
      }
    })

    languages.push({ key: 'en', icons: ['gb', 'us'], shortKey: 'EN', lang: 'English', percentage: 100, gauge: 'full' })
    languages.sort((a, b) => a.lang.localeCompare(b.lang))
    return languages
  }

  function calcPercentage (fileContent: any, enContent: any): number {
    const totalStrings = Object.keys(enContent).length
    let differentStrings = 0
    for (const key in fileContent) {
      if (Object.prototype.hasOwnProperty.call(fileContent, key) && fileContent[key] !== enContent[key]) {
        differentStrings++
      }
    }
    return (differentStrings / totalStrings) * 100
  }
}
