describe('/ftp', () => {
  it('should not serve a directory listing', () => {
    cy.request({ url: '/ftp', failOnStatusCode: false }).its('body').should('not.contain', 'listing directory /ftp')
  })

  it('should refuse to serve the confidential file /ftp/acquisitions.md', () => {
    cy.request({ url: '/ftp/acquisitions.md', failOnStatusCode: false }).its('status').should('eq', 403)
  })

  it('should refuse poison null byte attacks on /ftp', () => {
    cy.request({ url: '/ftp/coupons_2013.md.bak%2500.md', failOnStatusCode: false }).its('status').should('eq', 403)
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
})
