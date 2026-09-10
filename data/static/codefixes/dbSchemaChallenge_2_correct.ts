export function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    const rawCriteria = typeof req.query.q === 'string' && req.query.q !== 'undefined' ? req.query.q : ''
    const criteria = rawCriteria.substring(0, 200)
    models.sequelize.query('SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name', { replacements: { criteria: `%${criteria}%` } })
      .then(([products]: any) => {
        const dataString = JSON.stringify(products)
        for (let i = 0; i < products.length; i++) {
          products[i].name = req.__(products[i].name)
          products[i].description = req.__(products[i].description)
        }
        res.json(utils.queryResultToJson(products))
      }).catch((error: ErrorWithParent) => {
        next(error.parent)
      })
  }
}