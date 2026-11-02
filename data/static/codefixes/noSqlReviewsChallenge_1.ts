export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    const id = req.body.id
    if (id['$ne'] !== undefined) {
      res.status(400).send()
      return
    }
    if (!user?.data?.email) {
      res.status(401).send()
      return
    }

    db.reviewsCollection.update(
      { _id: id, author: user.data.email },
      { $set: { message: req.body.message } }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}