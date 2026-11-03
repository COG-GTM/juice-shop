export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    if (!user?.data?.email) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    if (typeof req.body.id !== 'string' || typeof req.body.message !== 'string') {
      res.status(400).json({ error: 'Invalid review id or message' })
      return
    }
    db.reviewsCollection.update(
      { _id: req.body.id, author: user.data.email },
      { $set: { message: req.body.message } },
      { multi: false }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        if (result.modified === 0) {
          res.status(403).json({ error: 'Not allowed to edit this review' })
          return
        }
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}