export function retrieveLoggedInUser () {
  return (req: Request, res: Response) => {
    let user
    let response: any
    const emptyUser = { id: undefined, email: undefined, lastLoginIp: undefined, profileImage: undefined }
    const exposableFields = ['id', 'email', 'lastLoginIp', 'profileImage']
    try {
      if (security.verify(req.cookies.token)) {
        user = security.authenticatedUsers.get(req.cookies.token)

        // Parse the fields parameter into an array, splitting by comma.
        // If not provided, both these variables will be undefined.
        const fieldsParam = req.query?.fields as string | undefined
        const requestedFields = fieldsParam ? fieldsParam.split(',').map(f => f.trim()) : []

        let baseUser: any = {}

        if (requestedFields.length > 0) {
          // When fields are specified, return only those of them which are not sensitive
          for (const field of requestedFields.filter(field => exposableFields.includes(field))) {
            if (user?.data[field as keyof typeof user.data] !== undefined) {
              baseUser[field] = user?.data[field as keyof typeof user.data]
            }
          }
        } else {
          // If no fields parameter, return standard fields (not password field)
          baseUser = {
            id: user?.data?.id,
            email: user?.data?.email,
            lastLoginIp: user?.data?.lastLoginIp,
            profileImage: user?.data?.profileImage
          }
        }

        response = { user: baseUser }
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