import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { TranslateModule } from '@ngx-translate/core'

import { NextChallengesScoreCardComponent } from './next-challenges-score-card.component'
import { DifficultyStarsComponent } from '../difficulty-stars/difficulty-stars.component'

describe('NextChallengesScoreCardComponent', () => {
    let component: NextChallengesScoreCardComponent
    let fixture: ComponentFixture<NextChallengesScoreCardComponent>

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [TranslateModule.forRoot(), DifficultyStarsComponent, NextChallengesScoreCardComponent]
        })
            .compileComponents()

        fixture = TestBed.createComponent(NextChallengesScoreCardComponent)
        component = fixture.componentInstance
        fixture.detectChanges()
    })

    it('should create', () => {
        expect(component).toBeTruthy()
    })

    it('should suggest nothing if there are no challenges', () => {
        expect(component.nextChallenges).toEqual([])
    })
})
