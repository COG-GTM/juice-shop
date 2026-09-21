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
    it('should be able to change password without passing current password', () => {
      cy.login({
        email: 'bender',
        password: 'OhG0dPlease1nsertLiquor!'
      })
      cy.window().then((window) => {
        cy.request({
          url: '/rest/user/change-password?new=slurmCl4ssic&repeat=slurmCl4ssic',
          headers: { Authorization: `Bearer=${window.localStorage.getItem('token')}` }
        })
      })
      cy.login({ email: 'bender', password: 'slurmCl4ssic' })
      cy.url().should('match', /\/search/)

      cy.expectChallengeSolved({ challenge: "Change Bender's Password" })
    })
  })
})
