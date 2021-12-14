// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const express = require('express')
const router = express.Router()
const bcrypt = require('bcryptjs')
const Users = require('../users/users-model')
const  { 
  checkPasswordLength,
  checkUsernameExists, 
  checkUsernameFree
} = require('./auth-middleware')

router.post('/register', checkUsernameFree, checkPasswordLength, async  (req, res, next) => {
  try {
    const {username, password} = req.body
    console.log(req.body)
    const newUser = {
      username, 
      password: bcrypt.hashSync(password, 8),
    }
    const created = await Users.add(newUser)
    res.status(200).json(created)
  } catch (err) {
    next(err)
  }
})

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */

router.post('/login', checkUsernameExists, async (req, res, next) => {
  try {
    const {username, password} = req.body
    const [userFromdDb] = await Users.findBy({username})
    if (!userFromdDb) {
      return next({message: 'Invalid credentials', status: 401})
    }

    const verifies = bcrypt.compareSync(password, userFromdDb.password)
    if (!verifies) {
      return next({message: 'Invalid credentials', status: 401})
    }

    req.session.user = userFromdDb
    res.json({status: 200, message: `Welcome ${username}`})
  } catch (err) {
    next(err)
  }
})

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */


router.get('/logout', async (req, res, next) => {
  try {
    if (req.session.user) {
      req.session.destroy((err) => {
        if (err) {
          res.json('how did we get here')
        } else {
          res.json({status: 200, message: 'logged out'})
        }
      })
    } else {
      res.json({status: 200, message: 'no session'})
    }
  } catch (err){
    next(err)
  }
})
/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router