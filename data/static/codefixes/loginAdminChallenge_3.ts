export function login () {
  function afterLogin (user: { data: User, bid: number }, res: Response, next: NextFunction) {
    BasketModel.findOrCreate({ where: { UserId: user.data.id } })
      .then(([basket]: [BasketModel, boolean]) => {
        const token = security.authorize(user)
        user.bid = basket.id // keep track of original basket
        security.authenticatedUsers.put(token, user)
        res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })
      }).catch((error: Error) => {
        next(error)
      })
  }

  return (req: Request, res: Response, next: NextFunction) => {
    models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL`,
      { bind: [ req.body.email, req.body.password ], model: models.User, plain: true })
      .then(async (authenticatedUser) => {
        const user = utils.queryResultToJson(authenticatedUser)
        if (!user.data?.id || !security.verifyPassword(req.body.password, user.data.password)) {
          res.status(401).send(res.__('Invalid email or password.'))
          return
        }
        if (authenticatedUser && security.isLegacyPasswordHash(user.data.password)) {
          await authenticatedUser.update({ password: req.body.password })
          user.data.password = authenticatedUser.password
        }
        if (user.data.totpSecret !== '') {
          res.status(401).json({
            status: 'totp_token_required',
            data: {
              tmpToken: security.authorize({
                userId: user.data.id,
                type: 'password_valid_needs_second_factor_token'
              })
            }
          })
        } else {
          afterLogin(user, res, next)
        }
      }).catch((error: Error) => {
        next(error)
      })
  }