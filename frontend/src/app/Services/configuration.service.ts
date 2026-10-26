/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { environment } from '../../environments/environment'
import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { catchError, map } from 'rxjs/operators'
import { type Observable } from 'rxjs'

interface ConfigResponse {
  config: Config
}
export interface Config {
  application: {
    domain: string
    name: string
    logo: string
    theme: string
    showGitHubLinks: boolean
    altcoinName: string
    privacyContactEmail: string
    social: {
      blueSkyUrl: string
      mastodonUrl: string
      twitterUrl: string
      facebookUrl: string
      slackUrl: string
      redditUrl: string
      pressKitUrl: string
      nftUrl: string
    }
    chatBot: {
      name: string
      avatar: string
      sampleQuestions: string[]
    }
    recyclePage: {
      topProductImage: string
      bottomProductImage: string
    }
    welcomeBanner: {
      showOnFirstStart: boolean
      title: string
      message: string
    }
    googleOauth: {
      clientId: string
      authorizedRedirects: any[]
    }
  }
  challenges: {
    codingChallengesEnabled: string
    restrictToTutorialsFirst: boolean
  }
  hackingInstructor: {
    isEnabled: boolean
    hintPlaybackSpeed: string
  }
  ctf: {
    showFlagsInNotifications: boolean
    showCountryDetailsInNotifications: string
    systemWideNotifications?: {
      url?: string
      pollFrequencySeconds?: number
    }
  }
}

@Injectable({
  providedIn: 'root'
})
export class ConfigurationService {
  private readonly http = inject(HttpClient)

  private readonly hostServer = environment.hostServer
  private readonly host = this.hostServer + '/rest'
  private configObservable: any

  getApplicationConfiguration (): Observable<Config> {
    if (this.configObservable) {
      return this.configObservable
    } else {
      this.configObservable = this.http.get<ConfigResponse>(this.host + '/application-configuration').pipe(map((response: ConfigResponse) => response.config, catchError((err) => { throw err })))
      return this.configObservable
    }
  }
}
