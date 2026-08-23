import { Component, EventEmitter, Input, type OnChanges, type OnInit, Output } from '@angular/core'
import { TranslateModule } from '@ngx-translate/core'

import { suggestNextChallenges } from '../../helpers/challenge-coverage'
import { type EnrichedChallenge } from '../../types/EnrichedChallenge'
import { DifficultyStarsComponent } from '../difficulty-stars/difficulty-stars.component'

@Component({
  selector: 'next-challenges-score-card',
  templateUrl: './next-challenges-score-card.component.html',
  styleUrls: ['./next-challenges-score-card.component.scss'],
  imports: [DifficultyStarsComponent, TranslateModule]
})
export class NextChallengesScoreCardComponent implements OnInit, OnChanges {
  @Input()
  public allChallenges: EnrichedChallenge[] = []

  @Output()
    challengeSelect = new EventEmitter<string>()

  public nextChallenges: EnrichedChallenge[] = []

  ngOnInit (): void {
    this.updateNextChallenges()
  }

  ngOnChanges (): void {
    this.updateNextChallenges()
  }

  private updateNextChallenges (): void {
    this.nextChallenges = suggestNextChallenges(this.allChallenges)
  }
}
