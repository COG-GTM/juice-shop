export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    const id = req.body.id
    if (typeof id !== 'string') {
      res.status(400).send()
      return
    }
    if (!user?.data?.email) {
      res.status(401).send()
      return
    }

    db.reviewsCollection.update(
      { _id: id },
      { $set: { message: req.body.message, author: user.data.email } }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}