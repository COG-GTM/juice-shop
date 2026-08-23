import { type ComponentFixture, TestBed } from '@angular/core/testing'
import { TranslateModule } from '@ngx-translate/core'

import { CategoryCoverageScoreCardComponent } from './category-coverage-score-card.component'
import { ScoreCardComponent } from '../score-card/score-card.component'

describe('CategoryCoverageScoreCardComponent', () => {
    let component: CategoryCoverageScoreCardComponent
    let fixture: ComponentFixture<CategoryCoverageScoreCardComponent>

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [TranslateModule.forRoot(), ScoreCardComponent, CategoryCoverageScoreCardComponent]
        })
            .compileComponents()

        fixture = TestBed.createComponent(CategoryCoverageScoreCardComponent)
        component = fixture.componentInstance
        fixture.detectChanges()
    })

    it('should create', () => {
        expect(component).toBeTruthy()
    })

    it('should emit the clicked category', () => {
        const emittedCategories: string[] = []
        component.categorySelect.subscribe((category) => emittedCategories.push(category))

        component.categorySelect.emit('XSS')

        expect(emittedCategories).toEqual(['XSS'])
    })
})
