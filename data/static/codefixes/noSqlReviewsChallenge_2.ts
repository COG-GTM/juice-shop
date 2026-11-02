export function updateProductReviews () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)
    if (!user?.data?.email) {
      return res.status(401).json({ error: 'Unauthorized' })
    }

    const id = req.body.id
    try {
      const result: { modified: number, original: Array<{ author: any }> } = await db.reviewsCollection.update(
        { _id: id },
        { $set: { message: req.body.message } },
        { multi: false }
      )
      res.json(result)
    } catch (err: unknown) {
      res.status(500).json(err)
    }
  }
}