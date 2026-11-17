/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Component, inject, OnInit } from '@angular/core'
import { DomSanitizer } from '@angular/platform-browser'
import { getSession } from '../Services/auth-session'
import { TranslateModule } from '@ngx-translate/core'
import { MatCardModule } from '@angular/material/card'

@Component({
  selector: 'app-last-login-ip',
  templateUrl: './last-login-ip.component.html',
  styleUrls: ['./last-login-ip.component.scss'],
  imports: [MatCardModule, TranslateModule]
})

export class LastLoginIpComponent implements OnInit {
  private readonly sanitizer = inject(DomSanitizer)

  lastLoginIp: any = '?'

  ngOnInit (): void {
    try {
      this.parseSession()
    } catch (err) {
      console.log(err)
    }
  }

  parseSession () {
    const session = getSession()
    if (session) {
      if (session.lastLoginIp) {

        this.lastLoginIp = this.sanitizer.bypassSecurityTrustHtml(`<small>${session.lastLoginIp}</small>`)
      }
    }
  }
}
