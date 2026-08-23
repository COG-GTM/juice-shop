import { Component, EventEmitter, Input, type OnChanges, type OnInit, Output } from '@angular/core'
import { TranslateModule } from '@ngx-translate/core'

import { type CategoryCoverage, calculateCategoryCoverages } from '../../helpers/challenge-coverage'
import { type EnrichedChallenge } from '../../types/EnrichedChallenge'
import { ScoreCardComponent } from '../score-card/score-card.component'

@Component({
  selector: 'category-coverage-score-card',
  templateUrl: './category-coverage-score-card.component.html',
  styleUrls: ['./category-coverage-score-card.component.scss'],
  imports: [ScoreCardComponent, TranslateModule]
})
export class CategoryCoverageScoreCardComponent implements OnInit, OnChanges {
  @Input()
  public allChallenges: EnrichedChallenge[] = []

  @Output()
    categorySelect = new EventEmitter<string>()

  public categoryCoverages: CategoryCoverage[] = []
  public solvedChallenges = 0

  ngOnInit (): void {
    this.updateCategoryCoverages()
  }

  ngOnChanges (): void {
    this.updateCategoryCoverages()
  }

  private updateCategoryCoverages (): void {
    this.categoryCoverages = calculateCategoryCoverages(this.allChallenges)
    this.solvedChallenges = this.allChallenges.filter((challenge) => challenge.solved).length
  }
}
