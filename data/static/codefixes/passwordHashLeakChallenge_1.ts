export function retrieveLoggedInUser () {
  return (req: Request, res: Response) => {
    let user
    let response: any
    const emptyUser = { id: undefined, email: undefined, lastLoginIp: undefined, profileImage: undefined }
    try {
      if (security.verify(req.cookies.token)) {
        user = security.authenticatedUsers.get(req.cookies.token)

        response = {
          user: {
            id: user?.data?.id,
            email: user?.data?.email,
            lastLoginIp: user?.data?.lastLoginIp,
            profileImage: user?.data?.profileImage
          }
        }
      } else {
        response = { user: emptyUser }
      }
    } catch (err) {
      response = { user: emptyUser }
    }
    if (req.query.callback === undefined) {
      res.json(response)
    } else {
      res.jsonp(response)
    }
  }
}