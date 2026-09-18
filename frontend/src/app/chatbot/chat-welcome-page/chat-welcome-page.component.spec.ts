/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { Router } from '@angular/router'
import { TranslateModule } from '@ngx-translate/core'
import { of } from 'rxjs'
import { ChatWelcomePageComponent } from './chat-welcome-page.component'
import { ConversationStorageService } from '../../Services/conversation-storage.service'
import { ConfigurationService } from '../../Services/configuration.service'

describe('ChatWelcomePageComponent', () => {
    let component: ChatWelcomePageComponent
    let fixture: ComponentFixture<ChatWelcomePageComponent>
    let router: any
    let conversationStorage: any
    let configurationService: any

    beforeEach(() => {
        router = {
            navigate: vi.fn().mockName('Router.navigate')
        }
        router.navigate.mockResolvedValue(true)
        conversationStorage = {
            generateId: vi.fn().mockName('ConversationStorageService.generateId'),
            getAll: vi.fn().mockName('ConversationStorageService.getAll'),
            delete: vi.fn().mockName('ConversationStorageService.delete'),
            deleteAll: vi.fn().mockName('ConversationStorageService.deleteAll')
        }
        conversationStorage.generateId.mockReturnValue('conv_42')
        conversationStorage.getAll.mockReturnValue([])
        configurationService = {
            getApplicationConfiguration: vi.fn().mockName('ConfigurationService.getApplicationConfiguration')
        }
        configurationService.getApplicationConfiguration.mockReturnValue(of({
            application: {
                chatBot: {
                    sampleQuestions: ['CHATBOT_PROMPT_RECOMMENDATION_SUMMER_PARTY']
                }
            }
        }))

        TestBed.configureTestingModule({
            imports: [
                TranslateModule.forRoot(),
                ChatWelcomePageComponent
            ],
            providers: [
                { provide: Router, useValue: router },
                { provide: ConversationStorageService, useValue: conversationStorage },
                { provide: ConfigurationService, useValue: configurationService }
            ]
        }).compileComponents()

        fixture = TestBed.createComponent(ChatWelcomePageComponent)
        component = fixture.componentInstance
        fixture.detectChanges()
    })

    it('should create', () => {
        expect(component).toBeTruthy()
    })

    it('should render the welcome screen sub-component', () => {
        const welcomeScreen = fixture.nativeElement.querySelector('app-chat-welcome-screen')
        expect(welcomeScreen).toBeTruthy()
    })

    it('should navigate to a new conversation with the initial message', () => {
        component.onMessageSent('Hello JuicyBot')

        expect(conversationStorage.generateId).toHaveBeenCalled()
        expect(router.navigate).toHaveBeenCalledWith(
            ['/chatbot/conversation', 'conv_42'],
            { queryParams: { initialMessage: 'Hello JuicyBot' } }
        )
    })

    it('should navigate when the welcome screen emits messageSent', () => {
        const welcomeScreen = fixture.debugElement.children[0]
        welcomeScreen.componentInstance.messageSent.emit('From the screen')

        expect(router.navigate).toHaveBeenCalledWith(
            ['/chatbot/conversation', 'conv_42'],
            { queryParams: { initialMessage: 'From the screen' } }
        )
    })

    it('should navigate to an existing conversation', () => {
        component.onConversationSelected('conv_1')

        expect(conversationStorage.generateId).not.toHaveBeenCalled()
        expect(router.navigate).toHaveBeenCalledWith(['/chatbot/conversation', 'conv_1'])
    })

    it('should navigate when the welcome screen emits conversationSelected', () => {
        const welcomeScreen = fixture.debugElement.children[0]
        welcomeScreen.componentInstance.conversationSelected.emit('conv_7')

        expect(router.navigate).toHaveBeenCalledWith(['/chatbot/conversation', 'conv_7'])
    })
})
