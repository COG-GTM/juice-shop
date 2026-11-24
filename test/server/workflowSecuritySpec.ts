/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import fs from 'node:fs'
import path from 'node:path'
import yaml from 'js-yaml'

const expect = chai.expect

const workflowDir = path.resolve('.github/workflows')
const botTokenWorkflows = fs.readdirSync(workflowDir)
  .filter(file => file.endsWith('.yml') && fs.readFileSync(path.join(workflowDir, file), 'utf8').includes('secrets.BOT_TOKEN'))

const untrustedExpression = /\$\{\{\s*github\.(event\.|ref_name|head_ref)/

function stepsOf (file: string): any[] {
  const workflow: any = yaml.load(fs.readFileSync(path.join(workflowDir, file), 'utf8'))
  return Object.values(workflow.jobs).flatMap((job: any) => job.steps ?? [])
}

describe('workflowSecurity', () => {
  it('finds the workflows that use BOT_TOKEN', () => {
    expect(botTokenWorkflows).to.include.members(['update-news-www.yml', 'update-news-www-legacy.yml'])
  })

  botTokenWorkflows.forEach(file => {
    describe(file, () => {
      it('never expands event data or ref names inside run scripts', () => {
        stepsOf(file).filter(step => step.run).forEach(step => {
          expect(step.run, step.name).to.not.match(untrustedExpression)
        })
      })

      it('does not persist credentials from any checkout', () => {
        stepsOf(file).filter(step => String(step.uses).startsWith('actions/checkout@')).forEach(step => {
          expect(step.with?.['persist-credentials'], step.name).to.equal(false)
        })
      })

      it('only exposes BOT_TOKEN to run steps after all other run steps', () => {
        const runSteps = stepsOf(file).filter(step => step.run)
        const firstWithToken = runSteps.findIndex(step => JSON.stringify(step.env ?? {}).includes('secrets.BOT_TOKEN'))
        expect(firstWithToken).to.equal(runSteps.length - 1)
      })
    })
  })
})
