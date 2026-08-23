import { type EnrichedChallenge } from '../types/EnrichedChallenge'
import { calculateCategoryCoverages, suggestNextChallenges } from './challenge-coverage'

function createChallenge (challengeOverwrites: Partial<EnrichedChallenge>): EnrichedChallenge {
    return {
        category: 'foobar',
        description: 'lorem ipsum',
        originalDescription: 'lorem ipsum',
        difficulty: 1,
        hasCodingChallenge: false,
        id: 1,
        key: 'challenge-1',
        mitigationUrl: 'https://owasp.example.com',
        name: 'challenge one',
        solved: false,
        codingChallengeStatus: 0,
        tagList: [],
        disabledEnv: null,
        tutorialOrder: null,
        ...challengeOverwrites
    } as EnrichedChallenge
}

describe('calculateCategoryCoverages', () => {
    it('should return an empty list for no challenges', () => {
        expect(calculateCategoryCoverages([])).toEqual([])
    })

    it('should count no solved challenges if nothing is solved yet', () => {
        const challenges = [
            createChallenge({ key: 'a', category: 'Injection' }),
            createChallenge({ key: 'b', category: 'XSS' })
        ]

        expect(calculateCategoryCoverages(challenges)).toEqual([
            { category: 'Injection', solvedChallenges: 0, availableChallenges: 1 },
            { category: 'XSS', solvedChallenges: 0, availableChallenges: 1 }
        ])
    })

    it('should count all challenges as solved if everything is solved', () => {
        const challenges = [
            createChallenge({ key: 'a', category: 'Injection', solved: true }),
            createChallenge({ key: 'b', category: 'Injection', solved: true })
        ]

        expect(calculateCategoryCoverages(challenges)).toEqual([
            { category: 'Injection', solvedChallenges: 2, availableChallenges: 2 }
        ])
    })

    it('should aggregate all challenges into a single entry if there is only one category', () => {
        const challenges = [
            createChallenge({ key: 'a', category: 'XSS', solved: true }),
            createChallenge({ key: 'b', category: 'XSS' }),
            createChallenge({ key: 'c', category: 'XSS' })
        ]

        expect(calculateCategoryCoverages(challenges)).toEqual([
            { category: 'XSS', solvedChallenges: 1, availableChallenges: 3 }
        ])
    })

    it('should sort the categories alphabetically', () => {
        const challenges = [
            createChallenge({ key: 'a', category: 'XSS' }),
            createChallenge({ key: 'b', category: 'Injection' })
        ]

        expect(calculateCategoryCoverages(challenges).map((coverage) => coverage.category))
            .toEqual(['Injection', 'XSS'])
    })
})

describe('suggestNextChallenges', () => {
    it('should return no suggestions if there are no challenges', () => {
        expect(suggestNextChallenges([])).toEqual([])
    })

    it('should return no suggestions if all challenges are solved', () => {
        const challenges = [
            createChallenge({ key: 'a', solved: true }),
            createChallenge({ key: 'b', category: 'XSS', solved: true })
        ]

        expect(suggestNextChallenges(challenges)).toEqual([])
    })

    it('should prefer challenges from the least covered category', () => {
        const challenges = [
            createChallenge({ key: 'a', category: 'Injection', difficulty: 1, solved: true }),
            createChallenge({ key: 'b', category: 'Injection', difficulty: 1 }),
            createChallenge({ key: 'c', category: 'XSS', difficulty: 3 })
        ]

        expect(suggestNextChallenges(challenges).map((challenge) => challenge.key))
            .toEqual(['c', 'b'])
    })

    it('should prefer easier challenges within the same category', () => {
        const challenges = [
            createChallenge({ key: 'a', category: 'XSS', difficulty: 5 }),
            createChallenge({ key: 'b', category: 'XSS', difficulty: 2 }),
            createChallenge({ key: 'c', category: 'XSS', difficulty: 4 })
        ]

        expect(suggestNextChallenges(challenges).map((challenge) => challenge.key))
            .toEqual(['b', 'c', 'a'])
    })

    it('should break ties on equal difficulty by challenge name', () => {
        const challenges = [
            createChallenge({ key: 'a', category: 'XSS', difficulty: 2, name: 'charlie' }),
            createChallenge({ key: 'b', category: 'XSS', difficulty: 2, name: 'alpha' }),
            createChallenge({ key: 'c', category: 'XSS', difficulty: 2, name: 'bravo' })
        ]

        expect(suggestNextChallenges(challenges).map((challenge) => challenge.key))
            .toEqual(['b', 'c', 'a'])
    })

    it('should never return more than the given limit', () => {
        const challenges = [
            createChallenge({ key: 'a', category: 'XSS' }),
            createChallenge({ key: 'b', category: 'XSS' }),
            createChallenge({ key: 'c', category: 'XSS' }),
            createChallenge({ key: 'd', category: 'XSS' })
        ]

        expect(suggestNextChallenges(challenges)).toHaveLength(3)
        expect(suggestNextChallenges(challenges, 1)).toHaveLength(1)
    })

    it('should skip challenges which are unavailable in the current environment', () => {
        const challenges = [
            createChallenge({ key: 'a', category: 'XSS', disabledEnv: 'Docker' }),
            createChallenge({ key: 'b', category: 'XSS' })
        ]

        expect(suggestNextChallenges(challenges).map((challenge) => challenge.key)).toEqual(['b'])
    })
})
