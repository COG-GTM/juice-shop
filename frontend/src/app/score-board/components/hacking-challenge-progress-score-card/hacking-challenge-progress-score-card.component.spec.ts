import { type ComponentFixture, TestBed } from '@angular/core/testing'

import { HackingChallengeProgressScoreCardComponent } from './hacking-challenge-progress-score-card.component'
import { provideTranslateService } from '@ngx-translate/core'
import { ScoreCardComponent } from '../score-card/score-card.component'

describe('HackingChallengeProgressScoreCardComponent', () => {
    let component: HackingChallengeProgressScoreCardComponent
    let fixture: ComponentFixture<HackingChallengeProgressScoreCardComponent>

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            providers: [provideTranslateService()],
            imports: [ ScoreCardComponent, HackingChallengeProgressScoreCardComponent]
        })
            .compileComponents()

        fixture = TestBed.createComponent(HackingChallengeProgressScoreCardComponent)
        component = fixture.componentInstance
        fixture.detectChanges()
    })

    it('should create', () => {
        expect(component).toBeTruthy()
    })
})
