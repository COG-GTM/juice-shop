describe('/#/juicy-nft', () => {
  describe('challenge "nftUnlock"', () => {
    it('should be possible to unlock the NFT with the private key derived from the seed phrase leaked in feedback', () => {
      cy.request('/api/Feedbacks').then((response) => {
        const comment: string = response.body.data.find((feedback: { comment: string }) => feedback.comment.includes('/juicy-nft')).comment
        const seedPhrase = /"([a-z ]+)"/.exec(comment)?.[1] ?? ''
        cy.task<string>('DeriveNftWalletPrivateKey', seedPhrase).then((privateKey: string) => {
          cy.visit('/#/juicy-nft')
          cy.get('#privateKey').type(privateKey, { log: false })
          cy.get('#privateKey').parents('form').find('button[type="submit"]').click()
          cy.expectChallengeSolved({ challenge: 'NFT Takeover' })
        })
      })
    })
  })
})
