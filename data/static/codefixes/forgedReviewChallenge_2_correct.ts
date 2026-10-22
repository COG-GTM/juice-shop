export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    if (!user?.data?.email) {
      res.status(401).json({ status: 'error', message: 'Unauthorized' })
      return
    }
    db.reviewsCollection.update(
      { _id: req.body.id, author: user.data.email },
      { $set: { message: req.body.message } },
      { multi: true }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        if (result.modified === 0) {
          res.status(403).json({ status: 'error', message: 'Not allowed to edit this review' })
          return
        }
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}