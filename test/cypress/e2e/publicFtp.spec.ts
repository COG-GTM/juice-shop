describe('/ftp', () => {
  describe('challenge "errorHandling"', () => {
    it('should leak information through error message accessing /ftp/easter.egg', () => {
      cy.visit('/ftp/easter.egg', { failOnStatusCode: false })

      cy.get('#stacktrace').then((elements) => {
        // eslint-disable-next-line @typescript-eslint/no-unused-expressions
        expect(!!elements.length).to.be.true
      })
      cy.expectChallengeSolved({ challenge: 'Error Handling' })
    })
  })

  describe('directory listing', () => {
    it('should not list the /ftp folder', () => {
      cy.request({ url: '/ftp', failOnStatusCode: false }).its('status').should('eq', 404)
    })

    it('should not serve confidential files from /ftp', () => {
      cy.request({ url: '/ftp/acquisitions.md', failOnStatusCode: false }).its('status').should('eq', 404)
      cy.request({ url: '/ftp/coupons_2013.md.bak%2500.md', failOnStatusCode: false }).its('status').should('eq', 404)
    })
  })
})
