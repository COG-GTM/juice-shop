export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    if (!user?.data?.email) {
      res.status(401).send()
      return
    }
    if (typeof req.body.id !== 'string' || typeof req.body.message !== 'string') {
      res.status(400).send()
      return
    }
    db.reviewsCollection.update(
      { _id: req.body.id },
      { $set: { message: req.body.message } }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        if (result.modified === 0) {
          res.status(403).send()
          return
        }
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}