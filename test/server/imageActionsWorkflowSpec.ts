/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import chai from 'chai'
import { safeLoad } from 'js-yaml'
const expect = chai.expect

describe('imageActionsWorkflow', () => {
  const workflow: any = safeLoad(fs.readFileSync(path.resolve('.github/workflows/image_actions.yml'), 'utf8'))
  const steps: any[] = Object.values<any>(workflow.jobs).flatMap((job: any) => job.steps)

  it('should pin every action to a full commit SHA', () => {
    const actions = steps.filter(step => step.uses).map(step => step.uses)
    expect(actions).to.have.lengthOf(3)
    for (const action of actions) {
      expect(action, action).to.match(/^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/)
    }
  })

  it('should grant no token permissions by default', () => {
    expect(workflow.permissions).to.deep.equal({})
  })

  it('should grant the compression job only contents and pull-requests write access', () => {
    for (const job of Object.values<any>(workflow.jobs)) {
      expect(job.permissions).to.deep.equal({ contents: 'write', 'pull-requests': 'write' })
    }
  })
})
