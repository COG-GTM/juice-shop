import { type EnrichedChallenge } from '../types/EnrichedChallenge'

export interface CategoryCoverage {
  category: string
  solvedChallenges: number
  availableChallenges: number
}

export function calculateCategoryCoverages (
  challenges: EnrichedChallenge[]
): CategoryCoverage[] {
  const coverageLookup = new Map<string, CategoryCoverage>()
  for (const challenge of challenges) {
    const coverage = coverageLookup.get(challenge.category) ??
      { category: challenge.category, solvedChallenges: 0, availableChallenges: 0 }
    coverage.availableChallenges++
    if (challenge.solved) {
      coverage.solvedChallenges++
    }
    coverageLookup.set(challenge.category, coverage)
  }
  return [...coverageLookup.values()].sort((a, b) => a.category.localeCompare(b.category))
}

export function coverageRatio (coverage: CategoryCoverage): number {
  if (coverage.availableChallenges === 0) {
    return 1
  }
  return coverage.solvedChallenges / coverage.availableChallenges
}

// suggests unsolved challenges from the least covered categories, preferring easier ones
export function suggestNextChallenges (
  challenges: EnrichedChallenge[],
  limit = 3
): EnrichedChallenge[] {
  const ratios = new Map(
    calculateCategoryCoverages(challenges).map((coverage) => [coverage.category, coverageRatio(coverage)])
  )
  return challenges
    .filter((challenge) => !challenge.solved && challenge.disabledEnv === null)
    .sort((a, b) => {
      const ratioDifference = ratios.get(a.category) - ratios.get(b.category)
      if (ratioDifference !== 0) {
        return ratioDifference
      }
      if (a.difficulty !== b.difficulty) {
        return a.difficulty - b.difficulty
      }
      return a.name.localeCompare(b.name)
    })
    .slice(0, limit)
}
