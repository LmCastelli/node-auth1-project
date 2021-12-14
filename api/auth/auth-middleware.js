const db = require("../../data/db-config");
const yup = require('yup')
/*
  If the user does not have a session saved in the server

  status 401
  {
    "message": "You shall not pass!"
  }
*/
function restricted(req, res, next) {
  if (req.session.user) {
    next()
  } else {
    next({status: 401, message: 'You shall not pass!'})
  }
}

/*
  If the username in req.body already exists in the database

  status 422
  {
    "message": "Username taken"
  }
*/
async function checkUsernameFree(req, res, next) {
  const notUnique = await db('users').where('username', req.body.username)
  if (notUnique.length === 0) {
    next()
  } else {
    next({status: 422, message: 'Username taken'})
  }
}

/*
  If the username in req.body does NOT exist in the database

  status 401
  {
    "message": "Invalid credentials"
  }
*/
async function checkUsernameExists(req, res, next) {
  const itExists = await db('users').where('username', req.body.username)

  if (itExists) {
    next()
  } else {
    next({status: 401, message: 'Invalid credentials'})
  }
}

/*
  If password is missing from req.body, or if it's 3 chars or shorter

  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
*/
const passwordSchema = yup.object().shape({
  password: yup.string()
    .required('Password must be longer than 3 chars')
    .min(4, 'Password must be longer than 3 chars')
})

async function checkPasswordLength(req, res, next) {
  try {
    const validated = await passwordSchema.validate(req.body)
    req.body = validated
    next()
  } catch (err) {
    next({status: 422, message: err.errors[0]})
  }
}


// Don't forget to add these to the `exports` object so they can be required in other modules
module.exports = {
  restricted, 
  checkUsernameFree,
  checkPasswordLength,
  checkUsernameExists,
}