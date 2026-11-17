/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import nodemailer from 'nodemailer'

import type { MailConfig } from './config.types'
import logger from './logger'

export interface Mail {
  to: string
  subject: string
  text: string
}

export async function sendMail ({ to, subject, text }: Mail) {
  const { from, smtp } = config.get<MailConfig>('mail')
  if (!smtp.host) {
    logger.warn('Outgoing mail is not configured (mail.smtp.host is empty), so no email was sent')
    return
  }
  const transport = nodemailer.createTransport({
    host: smtp.host,
    port: smtp.port,
    secure: smtp.secure,
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined
  })
  await transport.sendMail({ from, to, subject, text })
}
