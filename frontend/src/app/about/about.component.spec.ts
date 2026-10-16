/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TranslateModule, TranslateService } from '@ngx-translate/core'
import { EventEmitter, NO_ERRORS_SCHEMA } from '@angular/core'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { provideHttpClientTesting } from '@angular/common/http/testing'

import { MatCardModule } from '@angular/material/card'

import { of } from 'rxjs'
import { ConfigurationService } from '../Services/configuration.service'
import { FeedbackService } from '../Services/feedback.service'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'

import { AboutComponent } from './about.component'

describe('AboutComponent', () => {
    let component: AboutComponent
    let fixture: ComponentFixture<AboutComponent>
    let configurationService
    let feedbackService
    let translateService

    beforeEach(async () => {
        feedbackService = {
            find: vi.fn().mockName("FeedbackService.find")
        }
        feedbackService.find.mockReturnValue(of([]))
        configurationService = {
            getApplicationConfiguration: vi.fn().mockName("ConfigurationService.getApplicationConfiguration")
        }
        configurationService.getApplicationConfiguration.mockReturnValue(of({ application: {} }))
        translateService = {
            get: vi.fn().mockName("TranslateService.get")
        }
        translateService.get.mockReturnValue(of({}))
        translateService.onLangChange = new EventEmitter()
        translateService.onTranslationChange = new EventEmitter()
        translateService.onFallbackLangChange = new EventEmitter()
        translateService.onDefaultLangChange = new EventEmitter()

        TestBed.configureTestingModule({
            schemas: [NO_ERRORS_SCHEMA],
            imports: [MatCardModule,
                AboutComponent,
                TranslateModule.forRoot()],
            providers: [
                { provide: ConfigurationService, useValue: configurationService },
                { provide: FeedbackService, useValue: feedbackService },
                { provide: TranslateService, useValue: translateService },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting()
            ]
        })
            .compileComponents()
    })

    beforeEach(() => {
        fixture = TestBed.createComponent(AboutComponent)
        component = fixture.componentInstance
        fixture.detectChanges()
    })

    it('should create', () => {
        expect(component).toBeTruthy()
    })

    it('should set Mastodon link as obtained from configuration', () => {
        configurationService.getApplicationConfiguration.mockReturnValue(of({ application: { social: { mastodonUrl: 'MASTODON' } } }))
        component.ngOnInit()

        expect(component.mastodonUrl).toBe('MASTODON')
    })

    it('should set BlueSky link as obtained from configuration', () => {
        configurationService.getApplicationConfiguration.mockReturnValue(of({ application: { social: { blueSkyUrl: 'BLUESKY' } } }))
        component.ngOnInit()

        expect(component.blueSkyUrl).toBe('BLUESKY')
    })

    it('should set Twitter link as obtained from configuration', () => {
        configurationService.getApplicationConfiguration.mockReturnValue(of({ application: { social: { twitterUrl: 'TWITTER' } } }))
        component.ngOnInit()

        expect(component.twitterUrl).toBe('TWITTER')
    })

    it('should set Facebook link as obtained from configuration', () => {
        configurationService.getApplicationConfiguration.mockReturnValue(of({ application: { social: { facebookUrl: 'FACEBOOK' } } }))
        component.ngOnInit()

        expect(component.facebookUrl).toBe('FACEBOOK')
    })

    it('should set Slack link as obtained from configuration', () => {
        configurationService.getApplicationConfiguration.mockReturnValue(of({ application: { social: { slackUrl: 'SLACK' } } }))
        component.ngOnInit()

        expect(component.slackUrl).toBe('SLACK')
    })

    it('should set Reddit link as obtained from configuration', () => {
        configurationService.getApplicationConfiguration.mockReturnValue(of({ application: { social: { redditUrl: 'REDDIT' } } }))
        component.ngOnInit()

        expect(component.redditUrl).toBe('REDDIT')
    })

    it('should set press kit link as obtained from configuration', () => {
        configurationService.getApplicationConfiguration.mockReturnValue(of({ application: { social: { pressKitUrl: 'PRESS_KIT' } } }))
        component.ngOnInit()

        expect(component.pressKitUrl).toBe('PRESS_KIT')
    })

    it('should set NFT link as obtained from configuration', () => {
        configurationService.getApplicationConfiguration.mockReturnValue(of({ application: { social: { nftUrl: 'NFT' } } }))
        component.ngOnInit()

        expect(component.nftUrl).toBe('NFT')
    })

    it('should pass feedback comments to the gallery as plain text along with the rating', () => {
        const comment = '<iframe src="javascript:alert(`xss`)">'
        feedbackService.find.mockReturnValue(of([{ comment, rating: 3 }]))
        const addImage = vi.fn()
        component.galleryRef = { addImage } as any

        component.populateSlideshowFromFeedbacks()

        expect(addImage).toHaveBeenCalledWith({
            src: 'assets/public/images/carousel/1.jpg',
            args: { comment, stars: [true, true, true, false, false] }
        })
    })

    it('should clamp out-of-range ratings when deriving the stars', () => {
        feedbackService.find.mockReturnValue(of([{ comment: 'ok', rating: 42 }, { comment: 'meh', rating: -1 }]))
        const addImage = vi.fn()
        component.galleryRef = { addImage } as any

        component.populateSlideshowFromFeedbacks()

        expect(addImage.mock.calls[0][0].args.stars).toEqual([true, true, true, true, true])
        expect(addImage.mock.calls[1][0].args.stars).toEqual([false, false, false, false, false])
    })
})
