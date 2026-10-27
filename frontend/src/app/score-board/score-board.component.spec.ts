import { MatProgressSpinnerModule } from '@angular/material/progress-spinner'
import { provideHttpClientTesting } from '@angular/common/http/testing'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { RouterTestingModule } from '@angular/router/testing'
import { MatIconModule } from '@angular/material/icon'
import { TranslateModule } from '@ngx-translate/core'
import { of, throwError } from 'rxjs'

import { HackingChallengeProgressScoreCardComponent } from './components/hacking-challenge-progress-score-card/hacking-challenge-progress-score-card.component'
import { CodingChallengeProgressScoreCardComponent } from './components/coding-challenge-progress-score-card/coding-challenge-progress-score-card.component'
import { ChallengesUnavailableWarningComponent } from './components/challenges-unavailable-warning/challenges-unavailable-warning.component'
import { DifficultyOverviewScoreCardComponent } from './components/difficulty-overview-score-card/difficulty-overview-score-card.component'
import { TutorialModeWarningComponent } from './components/tutorial-mode-warning/tutorial-mode-warning.component'
import { WarningCardComponent } from './components/warning-card/warning-card.component'
import { ScoreCardComponent } from './components/score-card/score-card.component'
import { ScoreBoardComponent } from './score-board.component'
import { ConfigurationService } from '../Services/configuration.service'
import { ChallengeService } from '../Services/challenge.service'
import { type Challenge } from '../Models/challenge.model'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { HintService } from '../Services/hint.service'
import { SocketIoService } from '../Services/socket-io.service'

// allows to easily create a challenge with some overwrites
function createChallenge(challengeOverwrites: Partial<Challenge>): Challenge {
    return {
        name: 'foobar',
        key: 'challenge-1',
        category: 'category-blue',
        difficulty: 3,
        description: '',
        tags: '',
        disabledEnv: null,
        solved: false,
        tutorialOrder: null,
        hasTutorial: false,
        hasSnippet: false,
        codingChallengeStatus: 0,
        mitigationUrl: '',
        hasCodingChallenge: false,
        ...challengeOverwrites
    }
}

describe('ScoreBoardComponent', () => {
    let component: ScoreBoardComponent
    let fixture: ComponentFixture<ScoreBoardComponent>
    let challengeService
    let hintService
    let configService
    let socket

    beforeEach(async () => {
        challengeService = {
            find: vi.fn().mockName("ChallengeService.find")
        }
        hintService = {
            getAll: vi.fn().mockName("HintService.getAll"),
            put: vi.fn().mockName("HintService.put")
        }
        configService = {
            getApplicationConfiguration: vi.fn().mockName("ConfigurationService.getApplicationConfiguration")
        }
        socket = {
            on: vi.fn().mockName("Socket.on"),
            off: vi.fn().mockName("Socket.off")
        }
        await TestBed.configureTestingModule({
            imports: [TranslateModule.forRoot(),
                RouterTestingModule,
                MatProgressSpinnerModule,
                MatIconModule,
                ScoreBoardComponent,
                HackingChallengeProgressScoreCardComponent,
                CodingChallengeProgressScoreCardComponent,
                DifficultyOverviewScoreCardComponent,
                WarningCardComponent,
                ChallengesUnavailableWarningComponent,
                TutorialModeWarningComponent,
                ScoreCardComponent],
            providers: [
                { provide: ChallengeService, useValue: challengeService },
                { provide: HintService, useValue: hintService },
                { provide: ConfigurationService, useValue: configService },
                { provide: SocketIoService, useValue: { socket: () => socket } },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting()
            ]
        }).compileComponents()

        challengeService.find.mockReturnValue(of([
            createChallenge({
                id: 1,
                name: 'Challenge 1',
                key: 'challenge-1',
                category: 'category-blue',
                difficulty: 1,
                solved: true
            }),
            createChallenge({
                id: 2,
                name: 'Challenge 2',
                key: 'challenge-2',
                category: 'category-blue',
                difficulty: 5,
                solved: false,
                hasSnippet: true,
                codingChallengeStatus: 1
            }),
            createChallenge({
                id: 3,
                name: 'Challenge 3',
                key: 'challenge-3',
                category: 'category-red',
                difficulty: 3,
                hasSnippet: true,
                solved: false
            })
        ]))

        hintService.getAll.mockReturnValue(of([]))

        configService.getApplicationConfiguration.mockReturnValue(of({
            challenges: {
                restrictToTutorialsFirst: false,
                codingChallengesEnabled: 'solved',
                showHints: true,
                showMitigations: true
            },
            ctf: {
                showFlagsInNotifications: true
            },
            hackingInstructor: {
                isEnabled: true
            }
        }))

        fixture = TestBed.createComponent(ScoreBoardComponent)
        component = fixture.componentInstance
        fixture.detectChanges()
    })

    it('should not filter any challenges on default settings', (): void => {
        expect(component.filteredChallenges).toHaveLength(3)
    })

    it('should handle error when unlocking a hint', (): void => {
        hintService.put.mockReturnValue(throwError('Error'))
        console.log = vi.fn()
        component.unlockHint(123)
        expect(console.log).toHaveBeenCalledWith('Error')
    })

    it('should mark challenges as solved on "challenge solved" websocket', (): void => {
        expect(component.filteredChallenges.find((challenge) => challenge.key === 'challenge-3').solved).toBe(false)

        component.onChallengeSolvedWebsocket({
            key: 'challenge-3',
            name: '',
            challenge: '',
            flag: '',
            hidden: false,
            isRestore: false
        })

        expect(component.filteredChallenges.find((challenge) => challenge.key === 'challenge-3').solved).toBe(true)
    })

    it('should mark find it code challenges as solved on "code challenge solved" websocket', (): void => {
        expect(component.filteredChallenges.find((challenge) => challenge.key === 'challenge-3').codingChallengeStatus).toBe(0)

        component.onCodeChallengeSolvedWebsocket({
            key: 'challenge-3',
            codingChallengeStatus: 1
        })

        expect(component.filteredChallenges.find((challenge) => challenge.key === 'challenge-3').codingChallengeStatus).toBe(1)
    })

    it('should mark fix it code challenges as solved on "code challenge solved" websocket', (): void => {
        expect(component.filteredChallenges.find((challenge) => challenge.key === 'challenge-2').codingChallengeStatus).toBe(1)

        component.onCodeChallengeSolvedWebsocket({
            key: 'challenge-2',
            codingChallengeStatus: 2
        })

        expect(component.filteredChallenges.find((challenge) => challenge.key === 'challenge-2').codingChallengeStatus).toBe(2)
    })

    it('should remove the same socket handlers on destroy that were registered on init', (): void => {
        expect(socket.on).toHaveBeenCalledTimes(2)
        component.ngOnDestroy()
        expect(socket.off).toHaveBeenCalledTimes(2)
        for (const [event, handler] of socket.on.mock.calls) {
            expect(socket.off).toHaveBeenCalledWith(event, handler)
        }
    })

    it('should only refresh hints when unlocking a hint', (): void => {
        hintService.put.mockReturnValue(of({}))
        hintService.getAll.mockReturnValue(of([
            { id: 1, ChallengeId: 3, order: 1, text: 'first', unlocked: true },
            { id: 3, ChallengeId: 3, order: 3, text: 'third', unlocked: false },
            { id: 2, ChallengeId: 3, order: 2, text: 'second', unlocked: false }
        ]))
        challengeService.find.mockClear()
        configService.getApplicationConfiguration.mockClear()
        socket.on.mockClear()

        component.unlockHint(1, 'challenge-3')

        expect(challengeService.find).not.toHaveBeenCalled()
        expect(configService.getApplicationConfiguration).not.toHaveBeenCalled()
        expect(socket.on).not.toHaveBeenCalled()
        expect(component.lastUnlockedChallengeKey).toBe('challenge-3')
        expect(component.allChallenges.find((challenge) => challenge.key === 'challenge-3')).toEqual(expect.objectContaining({
            hintText: '1. first',
            nextHint: 2,
            hintsUnlocked: 1,
            hintsAvailable: 3
        }))
    })

    it('should keep solved state from websocket events after unlocking a hint', (): void => {
        hintService.put.mockReturnValue(of({}))
        component.onChallengeSolvedWebsocket({
            key: 'challenge-3',
            name: '',
            challenge: '',
            flag: '',
            hidden: false,
            isRestore: false
        })

        component.unlockHint(1, 'challenge-3')

        expect(component.filteredChallenges.find((challenge) => challenge.key === 'challenge-3').solved).toBe(true)
    })
})
