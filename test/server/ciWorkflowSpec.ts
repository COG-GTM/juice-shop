/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import yaml from 'js-yaml'
import { expect } from 'chai'

describe('ciWorkflow', () => {
  const workflow: any = yaml.load(fs.readFileSync('.github/workflows/ci.yml', 'utf8'))

  it('should pin every third-party action to a full commit hash', () => {
    for (const [jobName, job] of Object.entries<any>(workflow.jobs)) {
      for (const step of job.steps ?? []) {
        if (step.uses !== undefined && !String(step.uses).startsWith('./')) {
          expect(step.uses, `${jobName}: ${step.name}`).to.match(/@[0-9a-f]{40}$/)
        }
      }
    }
  })

  it('should limit the token handed to the Coveralls upload to read-only repository contents', () => {
    expect(workflow.jobs['coverage-report'].permissions).to.deep.equal({ contents: 'read' })
  })

  it('should default the workflow token to read-only repository contents', () => {
    expect(workflow.permissions).to.deep.equal({ contents: 'read' })
  })

  it('should not pipe a downloaded script into a shell', () => {
    for (const [jobName, job] of Object.entries<any>(workflow.jobs)) {
      for (const step of job.steps ?? []) {
        expect(String(step.run ?? ''), `${jobName}: ${step.name}`).to.not.match(/\|\s*(ba|z)?sh\b/)
      }
    }
  })

  it('should install a pinned Heroku CLI only after verifying its SHA-256 checksum', () => {
    const steps = workflow.jobs.heroku.steps
    const install = steps.find((step: any) => step.name === 'Install Heroku CLI')
    expect(install.env.HEROKU_CLI_VERSION).to.match(/^\d+\.\d+\.\d+$/)
    expect(install.env.HEROKU_CLI_SHA256).to.match(/^[0-9a-f]{64}$/)
    expect(install.run).to.match(/sha256sum --check --strict[\s\S]*tar --extract/)
    expect(steps[0].with['persist-credentials']).to.equal(false)
  })
})
