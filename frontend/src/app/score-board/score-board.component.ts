import { Component, NgZone, type OnDestroy, type OnInit, inject } from '@angular/core'
import { ActivatedRoute, Router } from '@angular/router'
import { DomSanitizer } from '@angular/platform-browser'
import { type Subscription, combineLatest, firstValueFrom } from 'rxjs'

import { fromQueryParams, toQueryParams } from './filter-settings/query-params-converters'
import { DEFAULT_FILTER_SETTING, type FilterSetting } from './filter-settings/FilterSetting'
import { type Config, ConfigurationService } from '../Services/configuration.service'
import { ChallengeService } from '../Services/challenge.service'
import { HintService } from '../Services/hint.service'
import { type Hint } from '../Models/hint.model'
import { filterChallenges } from './helpers/challenge-filtering'
import { SocketIoService } from '../Services/socket-io.service'
import { type EnrichedChallenge } from './types/EnrichedChallenge'
import { sortChallenges } from './helpers/challenge-sorting'
import { TranslateModule } from '@ngx-translate/core'
import { ChallengeCardComponent } from './components/challenge-card/challenge-card.component'
import { TutorialModeWarningComponent } from './components/tutorial-mode-warning/tutorial-mode-warning.component'
import { ChallengesUnavailableWarningComponent } from './components/challenges-unavailable-warning/challenges-unavailable-warning.component'
import { MatProgressSpinner } from '@angular/material/progress-spinner'
import { FilterSettingsComponent } from './components/filter-settings/filter-settings.component'
import { NgClass } from '@angular/common'
import { DifficultyOverviewScoreCardComponent } from './components/difficulty-overview-score-card/difficulty-overview-score-card.component'
import { CodingChallengeProgressScoreCardComponent } from './components/coding-challenge-progress-score-card/coding-challenge-progress-score-card.component'
import { HackingChallengeProgressScoreCardComponent } from './components/hacking-challenge-progress-score-card/hacking-challenge-progress-score-card.component'

interface ChallengeSolvedWebsocket {
  key: string
  name: string
  challenge: string
  flag: string
  hidden: boolean
  isRestore: boolean
}
interface CodeChallengeSolvedWebsocket {
  key: string
  codingChallengeStatus: 0 | 1 | 2
}

type HintFields = Pick<EnrichedChallenge, 'hintText' | 'nextHint' | 'hintsUnlocked' | 'hintsAvailable'>

function groupHintsByChallenge (hints: Hint[]): Map<number, Hint[]> {
  const hintsByChallenge = new Map<number, Hint[]>()
  for (const hint of hints) {
    const challengeHints = hintsByChallenge.get(hint.ChallengeId)
    if (challengeHints) {
      challengeHints.push(hint)
    } else {
      hintsByChallenge.set(hint.ChallengeId, [hint])
    }
  }
  return hintsByChallenge
}

function hintFields (hints: Hint[]): HintFields {
  const unlocked = hints.filter((hint) => hint.unlocked)
  const locked = hints.filter((hint) => !hint.unlocked).sort((a, b) => a.order - b.order)
  return {
    hintText: unlocked.map((hint) => hint.order + '. ' + hint.text).join('\n\n'),
    nextHint: locked[0]?.id,
    hintsUnlocked: unlocked.length,
    hintsAvailable: hints.length
  }
}

@Component({
  selector: 'app-score-board',
  templateUrl: './score-board.component.html',
  styleUrls: ['./score-board.component.scss'],
  imports: [HackingChallengeProgressScoreCardComponent, CodingChallengeProgressScoreCardComponent, DifficultyOverviewScoreCardComponent, FilterSettingsComponent, MatProgressSpinner, ChallengesUnavailableWarningComponent, TutorialModeWarningComponent, ChallengeCardComponent, NgClass, TranslateModule]
})
export class ScoreBoardComponent implements OnInit, OnDestroy {
  private readonly challengeService = inject(ChallengeService)
  private readonly hintService = inject(HintService)
  private readonly configurationService = inject(ConfigurationService)
  private readonly sanitizer = inject(DomSanitizer)
  private readonly ngZone = inject(NgZone)
  private readonly io = inject(SocketIoService)
  private readonly router = inject(Router)
  private readonly route = inject(ActivatedRoute)

  public allChallenges: EnrichedChallenge[] = []
  public filteredChallenges: EnrichedChallenge[] = []
  public filterSetting: FilterSetting = structuredClone(DEFAULT_FILTER_SETTING)
  public applicationConfiguration: Config | null = null
  public lastUnlockedChallengeKey: string | null = null

  public isInitialized = false

  private readonly subscriptions: Subscription[] = []
  private dataLoaderSubscription: Subscription | null = null
  private hintRefreshSubscription: Subscription | null = null

  private readonly challengeSolvedHandler = this.onChallengeSolvedWebsocket.bind(this)
  private readonly codeChallengeSolvedHandler = this.onCodeChallengeSolvedWebsocket.bind(this)

  ngOnInit (): void {
    this.loadData()

    const routerSubscription = this.route.queryParams.subscribe((queryParams) => {
      this.filterSetting = fromQueryParams(queryParams)
      this.filterAndUpdateChallenges()
    })
    this.subscriptions.push(routerSubscription)

    this.io.socket().on('challenge solved', this.challengeSolvedHandler)
    this.io.socket().on('code challenge solved', this.codeChallengeSolvedHandler)
  }

  ngOnDestroy (): void {
    this.io.socket().off('challenge solved', this.challengeSolvedHandler)
    this.io.socket().off('code challenge solved', this.codeChallengeSolvedHandler)
    this.dataLoaderSubscription?.unsubscribe()
    this.hintRefreshSubscription?.unsubscribe()
    for (const subscription of this.subscriptions) {
      subscription.unsubscribe()
    }
  }

  loadData (): void {
    this.dataLoaderSubscription?.unsubscribe()
    this.dataLoaderSubscription = combineLatest([
      this.challengeService.find({ sort: 'name' }),
      this.hintService.getAll(),
      this.configurationService.getApplicationConfiguration()
    ]).subscribe(([challenges, hints, applicationConfiguration]) => {
      this.applicationConfiguration = applicationConfiguration

      const hintsByChallenge = groupHintsByChallenge(hints)
      this.allChallenges = challenges.map((challenge) => {
        return {
          ...challenge,
          ...hintFields(hintsByChallenge.get(challenge.id) ?? []),
          tagList: challenge.tags ? challenge.tags.split(',').map((tag) => tag.trim()) : [],
          originalDescription: challenge.description as string,
          description: this.sanitizer.bypassSecurityTrustHtml(challenge.description as string)
        }
      })
      this.filterAndUpdateChallenges()
      this.isInitialized = true
    })
  }

  refreshHints (): void {
    this.hintRefreshSubscription?.unsubscribe()
    this.hintRefreshSubscription = this.hintService.getAll().subscribe({
      next: (hints) => {
        const hintsByChallenge = groupHintsByChallenge(hints)
        this.allChallenges = this.allChallenges.map((challenge) => ({
          ...challenge,
          ...hintFields(hintsByChallenge.get(challenge.id) ?? [])
        }))
        this.filterAndUpdateChallenges()
      },
      error: (err) => { console.log(err) }
    })
  }

  onFilterSettingUpdate (filterSetting: FilterSetting) {
    this.router.navigate([], {
      queryParams: toQueryParams(filterSetting)
    })
  }

  onChallengeSolvedWebsocket (data?: ChallengeSolvedWebsocket) {
    if (!data) {
      return
    }

    this.allChallenges = this.allChallenges.map((challenge) => {
      if (challenge.key === data.key) {
        return {
          ...challenge,
          solved: true
        }
      }
      return challenge
    })
    this.filterAndUpdateChallenges()
    // manually trigger angular change detection... :(
    // unclear why this is necessary, possibly because the socket.io callback is not running inside angular
    this.ngZone.run(() => {})
  }

  onCodeChallengeSolvedWebsocket (data?: CodeChallengeSolvedWebsocket) {
    if (!data) {
      return
    }

    this.allChallenges = this.allChallenges.map((challenge) => {
      if (challenge.key === data.key) {
        return {
          ...challenge,
          codingChallengeStatus: data.codingChallengeStatus
        }
      }
      return challenge
    })
    this.filterAndUpdateChallenges()
    // manually trigger angular change detection... :(
    // unclear why this is necessary, possibly because the socket.io callback is not running inside angular
    this.ngZone.run(() => {})
  }

  filterAndUpdateChallenges (): void {
    this.filteredChallenges = sortChallenges(
      filterChallenges(this.allChallenges, {
        ...this.filterSetting,
        restrictToTutorialChallengesFirst: this.applicationConfiguration?.challenges?.restrictToTutorialsFirst ?? true
      })
    )
  }

  // angular helper to speed up challenge rendering
  getChallengeKey (index: number, challenge: EnrichedChallenge): string {
    return challenge.key
  }

  reset () {
    this.router.navigate([], {
      queryParams: toQueryParams(DEFAULT_FILTER_SETTING)
    })
  }

  openCodingChallengeDialog (challengeKey: string) {
    this.router.navigate(['/coding-challenge', challengeKey])
  }

  async repeatChallengeNotification (challengeKey: string) {
    const challenge = this.allChallenges.find((challenge) => challenge.key === challengeKey)
    await firstValueFrom(this.challengeService.repeatNotification(encodeURIComponent(challenge.name)))
  }

  unlockHint (hintId: number, challengeKey?: string) {
    this.lastUnlockedChallengeKey = challengeKey ?? null
    this.hintService.put(hintId, { unlocked: true }).subscribe({
      next: () => {
        this.refreshHints()
      },
      error: (err) => { console.log(err) }
    })
  }

}
