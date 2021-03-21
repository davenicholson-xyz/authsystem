const { genSalt, hash, compare } = require("bcrypt");
const jwt = require("jsonwebtoken");

module.exports.encryptPassword = async (clearPassword) => {
  const salt = await genSalt();
  const epassword = await hash(clearPassword, salt);
  return epassword;
};

//

module.exports.checkPassword = async (clearpassword, password) => {
  const checked = await compare(clearpassword, password);
  return checked;
};

module.exports.createJWT = (userid, secret) => {
  return jwt.sign({ id: userid }, secret, { expiresIn: 360000 });
};

module.exports.requireAuth = (req, res, next) => {
  if (req.auth.token) {
    jwt.verify(req.auth.token, req.auth.secret, (err, decodedToken) => {
      if (err) {
        res.redirect(req.auth.redirect);
      } else {
        next();
      }
    });
  } else {
    console.log("Unauthorized... no JWT set");
    res.redirect(req.auth.redirect);
  }
};

module.exports.parseCookies = (cookie_string) => {
  let cookies = {};
  cookie_string.split(";").forEach((c) => {
    let ck = c.split("=");
    cookies[ck[0].trim()] = ck[1];
  });
  return cookies;
};
