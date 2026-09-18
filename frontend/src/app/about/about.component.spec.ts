/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { TranslateModule, TranslateService } from '@ngx-translate/core'
import { EventEmitter, NO_ERRORS_SCHEMA } from '@angular/core'
import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { provideHttpClientTesting } from '@angular/common/http/testing'

import { MatCardModule } from '@angular/material/card'

import { of, throwError } from 'rxjs'
import { ConfigurationService } from '../Services/configuration.service'
import { FeedbackService } from '../Services/feedback.service'
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http'
import { DomSanitizer } from '@angular/platform-browser'
import { Gallery } from 'ng-gallery'

import { AboutComponent } from './about.component'

describe('AboutComponent', () => {
    let component: AboutComponent
    let fixture: ComponentFixture<AboutComponent>
    let configurationService
    let translateService
    let feedbackService
    let galleryRef
    let gallery
    let bypassSecurityTrustHtml

    beforeEach(async () => {
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
        feedbackService = {
            find: vi.fn().mockName("FeedbackService.find")
        }
        feedbackService.find.mockReturnValue(of([]))
        galleryRef = {
            addImage: vi.fn().mockName("GalleryRef.addImage")
        }
        gallery = {
            ref: vi.fn().mockName("Gallery.ref").mockReturnValue(galleryRef)
        }

        TestBed.configureTestingModule({
            schemas: [NO_ERRORS_SCHEMA],
            imports: [MatCardModule,
                AboutComponent,
                TranslateModule.forRoot()],
            providers: [
                { provide: ConfigurationService, useValue: configurationService },
                { provide: TranslateService, useValue: translateService },
                { provide: FeedbackService, useValue: feedbackService },
                { provide: Gallery, useValue: gallery },
                provideHttpClient(withInterceptorsFromDi()),
                provideHttpClientTesting()
            ]
        })
            .compileComponents()
    })

    beforeEach(() => {
        bypassSecurityTrustHtml = vi.spyOn(TestBed.inject(DomSanitizer), 'bypassSecurityTrustHtml')
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

    it('should not set social links when configuration retrieval fails', () => {
        const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {})
        configurationService.getApplicationConfiguration.mockReturnValue(throwError(() => new Error('Config error')))

        expect(() => { component.ngOnInit() }).not.toThrow()
        expect(component.twitterUrl).toBeUndefined()
        expect(consoleError).toHaveBeenCalled()

        consoleError.mockRestore()
    })

    it('should add a gallery image with sanitized star caption for each feedback', () => {
        feedbackService.find.mockReturnValue(of([{ comment: 'First', rating: 5 }, { comment: 'Second', rating: 1 }]))
        galleryRef.addImage.mockClear()
        bypassSecurityTrustHtml.mockClear()

        component.ngOnInit()

        expect(bypassSecurityTrustHtml).toHaveBeenCalledTimes(2)
        expect(bypassSecurityTrustHtml.mock.calls[0][0]).toBe('<figcaption><p class="feedback-comment">First</p><div class="feedback-stars">(<i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i>)</div></figcaption>')
        expect(bypassSecurityTrustHtml.mock.calls[1][0]).toBe('<figcaption><p class="feedback-comment">Second</p><div class="feedback-stars">(<i class="fas fa-star"></i><i class="far fa-star"></i><i class="far fa-star"></i><i class="far fa-star"></i><i class="far fa-star"></i>)</div></figcaption>')
        expect(galleryRef.addImage).toHaveBeenCalledTimes(2)
        expect(galleryRef.addImage.mock.calls[0][0].src).toBe('assets/public/images/carousel/1.jpg')
        expect(galleryRef.addImage.mock.calls[0][0].args).toBe(bypassSecurityTrustHtml.mock.results[0].value)
        expect(galleryRef.addImage.mock.calls[1][0].src).toBe('assets/public/images/carousel/2.jpg')
    })

    it('should cycle through the carousel images when there are more feedbacks than images', () => {
        feedbackService.find.mockReturnValue(of(Array.from({ length: 8 }, (_, i) => ({ comment: `Comment ${i}`, rating: 3 }))))
        galleryRef.addImage.mockClear()

        component.ngOnInit()

        expect(galleryRef.addImage).toHaveBeenCalledTimes(8)
        expect(galleryRef.addImage.mock.calls[7][0].src).toBe(galleryRef.addImage.mock.calls[0][0].src)
    })

    it('should not add gallery images when feedback retrieval fails', () => {
        const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {})
        feedbackService.find.mockReturnValue(throwError(() => new Error('Feedback error')))
        galleryRef.addImage.mockClear()

        expect(() => { component.ngOnInit() }).not.toThrow()
        expect(galleryRef.addImage).not.toHaveBeenCalled()
        expect(consoleError).toHaveBeenCalled()

        consoleError.mockRestore()
    })
})
