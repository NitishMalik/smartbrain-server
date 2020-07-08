const jwt = require('jsonwebtoken');

// Redis Setup
const redis = require('redis');
//Update host for production
const redisClient = redis.createClient({ host: '127.0.0.1' })

const setToken = (key, value) => Promise.resolve(redisClient.set(key, value));
const signToken = (userDetail) => {
  const jwtPayload = { userDetail };
  return jwt.sign(jwtPayload, 'JWT_SECRET', { expiresIn: '2 days' });
}

const createSession = (user) => {
  const { email, id } = user;
  const token = signToken(email);
  console.log(token);
  return setToken(token, id)
    .then(() => {
      return { success: 'true', userId: id, token, user }
    })
    .catch(err => console.log(err));
}

const getAuthTokenId = (req, res) => {
  const { authorization } = req;
  return redisClient.get(authorization, (err, response) => {
    if (err || !response) {
      return res.status(401).send('Unauthorized');
    }
    return res.json({ id: response });
  })
}

const handleSignin = (db, bcrypt, req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return Promise.reject('incorrect form submission');
  }
  console.log("I am here");
  return db.select('email', 'hash').from('login')
    .where('email', '=', email)
    .then(data => {
      const isValid = bcrypt.compareSync(password, data[0].hash);
      if (isValid) {
        return db.select('*').from('users')
          .where('email', '=', email)
          .then(user => {
            console.log(user);
            return user[0]
          })
          .catch(err => Promise.reject('unable to get user'))
      } else {
        return Promise.reject('wrong credentials')
      }
    })
    .catch(err => Promise.reject('wrong credentials'))
}

const signinAuthentication = (db, bcrypt) => (req, res) => {
  const { authorization } = req.headers;
  return authorization ? getAuthTokenId(req, res)
    : handleSignin(db, bcrypt, req, res)
      .then(data => data.id && data.email ? createSession(data) : Promise.reject(data))
      .then(session => res.json(session))
      .catch(err => res.status(400).json(err));

}
module.exports = {
  signinAuthentication,
  redisClient
}