/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TranslateService, TranslateModule } from '@ngx-translate/core'
import { ChallengeService } from '../Services/challenge.service'
import { ConfigurationService } from '../Services/configuration.service'
import { ChangeDetectorRef, Component, NgZone, type OnInit, inject } from '@angular/core'
import { CookieService } from 'ngy-cookie'
import { CountryMappingService } from '../Services/country-mapping.service'
import { SocketIoService } from '../Services/socket-io.service'
import { UserService } from '../Services/user.service'
import { MatIconModule } from '@angular/material/icon'
import { MatButtonModule } from '@angular/material/button'
import { MatCardModule } from '@angular/material/card'
import { LowerCasePipe } from '@angular/common'
import { firstValueFrom } from 'rxjs'
import { SnackBarHelperService } from '../Services/snack-bar-helper.service'
import { Router } from '@angular/router'

interface ChallengeSolvedMessage {
  challenge: string
  hidden?: any
  isRestore?: any
  flag: any
  key?: any
  codingChallenge?: boolean
}

interface ChallengeSolvedNotification {
  key: string
  message: string
  flag: string
  country?: { code: string, name: string }
  copied: boolean
  codingChallenge?: boolean;
}

@Component({
  selector: 'app-challenge-solved-notification',
  templateUrl: './challenge-solved-notification.component.html',
  styleUrls: ['./challenge-solved-notification.component.scss'],
  imports: [MatCardModule, MatButtonModule, MatIconModule, LowerCasePipe, TranslateModule]
})
export class ChallengeSolvedNotificationComponent implements OnInit {
  private readonly ngZone = inject(NgZone)
  private readonly configurationService = inject(ConfigurationService)
  private readonly challengeService = inject(ChallengeService)
  private readonly countryMappingService = inject(CountryMappingService)
  private readonly translate = inject(TranslateService)
  private readonly cookieService = inject(CookieService)
  private readonly ref = inject(ChangeDetectorRef)
  private readonly io = inject(SocketIoService)
  private readonly userService = inject(UserService)
  private readonly snackBarHelperService = inject(SnackBarHelperService)
  private readonly router = inject(Router)

  public notifications: ChallengeSolvedNotification[] = []
  public showCtfFlagsInNotifications = false
  public showCtfCountryDetailsInNotifications = 'none'
  public countryMap?: any
  public codingChallengesEnabled = "solved"

  ngOnInit (): void {
    this.ngZone.runOutsideAngular(() => {
      this.io.socket().on('challenge solved', (data: ChallengeSolvedMessage) => {
        if (data?.challenge) {
          const shownNotification = this.notifications.find(({ key }) => key === data.key)
          if (shownNotification) {
            if (data.flag && !shownNotification.flag) {
              shownNotification.flag = data.flag
              this.ref.detectChanges()
            }
            this.io.socket().emit('notification received', data.flag, localStorage.getItem('token'))
            return
          }
          if (!data.hidden) {
            this.showNotification(data)
          }
          if (!data.isRestore) {
            this.saveProgress()
            if (!data.hidden) {
              import('../../confetti').then(module => {
                module.shootConfetti()
              })
            }
          }
          this.io.socket().emit('notification received', data.flag, localStorage.getItem('token'))
        }
      })
    })

    this.userService.getLoggedInState().subscribe(() => {
      this.io.authenticate()
    })

    this.configurationService.getApplicationConfiguration().subscribe((config) => {
      if (config?.ctf) {
        if (config.ctf.showFlagsInNotifications) {
          this.showCtfFlagsInNotifications = config.ctf.showFlagsInNotifications
        } else {
          this.showCtfFlagsInNotifications = false
        }

        if (config.ctf.showCountryDetailsInNotifications) {
          this.showCtfCountryDetailsInNotifications = config.ctf.showCountryDetailsInNotifications

          if (config.ctf.showCountryDetailsInNotifications !== 'none') {
            this.countryMappingService.getCountryMapping().subscribe({
              next: (countryMap: any) => {
                this.countryMap = countryMap
              },
              error: (err) => { console.log(err) }
            })
          }
        } else {
          this.showCtfCountryDetailsInNotifications = 'none'
        }
      }
    })
  }

  closeNotification (index: number, shiftKey = false) {
    if (shiftKey) {
      this.ngZone.runOutsideAngular(() => {
        this.io.socket().emit('verifyCloseNotificationsChallenge', this.notifications, localStorage.getItem('token'))
      })
      this.notifications = []
    } else {
      this.notifications.splice(index, 1)
    }
    this.ref.detectChanges()
  }

  showNotification (challenge: ChallengeSolvedMessage) {
    firstValueFrom(this.translate.get('CHALLENGE_SOLVED', { challenge: challenge.challenge }))
      .then((message) => {
        let country
        if (this.showCtfCountryDetailsInNotifications && this.showCtfCountryDetailsInNotifications !== 'none') {
          country = this.countryMap[challenge.key]
        }
        this.notifications.push({
          message,
          key: challenge.key,
          flag: challenge.flag,
          country,
          copied: false,
          codingChallenge: challenge.codingChallenge ?? false,
        })
        this.ref.detectChanges()
      })
  }

  saveProgress () {
    this.challengeService.continueCode().subscribe({
      next: (continueCode) => {
        if (!continueCode) {
          throw (new Error('Received invalid continue code from the server!'))
        }
        const expires = new Date()
        expires.setFullYear(expires.getFullYear() + 1)
        this.cookieService.put('continueCode', continueCode, { expires })
      },
      error: (err) => { console.log(err) }
    })
  }

  copyToClipboard (text: string) {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).then(() => {
        this.snackBarHelperService.open('COPY_SUCCESS', 'confirmBar')
      })
    }
  }

  navigateToChallenge(challengeKey: string) {
    if (!challengeKey) {
      return
    }
    this.ngZone.run(() => {
      void this.router.navigate(['/coding-challenge', challengeKey])
    })
  }
}
