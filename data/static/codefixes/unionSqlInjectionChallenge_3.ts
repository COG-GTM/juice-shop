export function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    const query = req.query.q
    if (query !== undefined && typeof query !== 'string') {
      res.status(400).json({ status: 'error', message: 'Invalid search query' })
      return
    }
    let criteria = query === undefined || query === 'undefined' ? '' : query
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
    // only allow apple or orange related searches
    if (!criteria.startsWith("apple") || !criteria.startsWith("orange")) {
      res.status(400).send()
      return
    }
    models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
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