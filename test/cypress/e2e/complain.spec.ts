describe('/#/complain', () => {
  beforeEach(() => {
    cy.login({
      email: 'admin',
      password: 'admin123'
    })

    cy.visit('/#/complain')
  })

  describe('challenge "uploadSize"', () => {
    it('should be possible to upload files greater 100 KB directly through backend', () => {
      cy.window().then(async () => {
        const over100KB = Array.apply(null, new Array(11000)).map(

          String.prototype.valueOf,
          '1234567890'
        )
        const blob = new Blob(over100KB, { type: 'application/pdf' })

        const data = new FormData()
        data.append('file', blob, 'invalidSizeForClient.pdf')

        await fetch(`${Cypress.config('baseUrl')}/file-upload`, {
          method: 'POST',
          cache: 'no-cache',
          body: data
        })
      })
      cy.expectChallengeSolved({ challenge: 'Upload Size' })
    })
  })

  describe('challenge "deprecatedInterface"', () => {
    it('should be possible to upload XML files', () => {
      cy.get('#complaintMessage').type('XML all the way!')
      cy.get('#file').selectFile('test/files/deprecatedTypeForServer.xml')
      cy.get('#submitButton').click()
      cy.expectChallengeSolved({ challenge: 'Deprecated Interface' })
    })
  })
})
