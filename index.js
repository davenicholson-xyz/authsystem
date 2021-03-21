const express = require("express");
const { authError } = require("./errors");
const { encryptPassword, createJWT, checkPassword, parseCookies, requireAuth } = require("./helpers");
const auth_router = express.Router();
const jwt = require("jsonwebtoken");

module.exports.authsystem = (model, options = {}) => {
  return (req, res, next) => {
    req.app.use(express.json());

    options = {
      user_field: "email",
      secret: "secretkey",
      maxAge: 3600000,
      redirect: "/",
      static: { pages: ["secret"] },
    };

    req.auth = {
      secret: options.secret,
      redirect: options.redirect,
    };

    const cookies = parseCookies(req.headers.cookie);
    const token = cookies.access_token;
    if (token) {
      req.auth.token = token;
      jwt.verify(req.auth.token, options.secret, async (err, decoded) => {
        if (err) {
          req.user = null;
          req.app.locals.user = null;
          res.cookie("access_token", null, { httpOnly: true, maxAge: 0 });
        } else {
          try {
            req.user = await model.findById(decoded.id);
            req.user.set("password", undefined, { strict: false });
            req.app.locals.user = req.user;
          } catch (err) {
            next("jwt auth error");
          }
        }
      });
    } else {
      req.user = null;
      req.app.locals.user = null;
    }

    let root = options.static.root || "./public";
    for (let route of options.static.pages) {
      req.app.get(`/${route}`, requireAuth, (req, res, next) => {
        res.sendFile(`${route}.html`, { root });
      });
    }

    auth_router.get("/", (req, res) => res.json({ default: "true" }));

    auth_router.post("/register", async (req, res, next) => {
      req.body.password = req.body.password || "";
      try {
        const user = await model.create(req.body);
        user.password = await encryptPassword(req.body.password);
        await user.save();
        const token = createJWT(user._id, options.secret);
        res.cookie("access_token", token, { httpOnly: true, maxAge: options.maxAge * 1000 });
        res.json({ token });
      } catch (err) {
        next(authError(err));
      }
    });

    auth_router.post("/signin", async (req, res, next) => {
      try {
        const user = await model.findOne({}).where(options.user_field, req.body[options.user_field]);
        if (user) {
          const pmatch = await checkPassword(req.body.password, user.password);
          if (pmatch) {
            const token = createJWT(user._id, options.secret);
            res.cookie("access_token", token, { httpOnly: true, maxAge: options.maxAge * 1000 });
            res.json({ token });
          } else {
            next("incorrect email/password");
          }
        } else {
          next("incorrect email/password");
        }
      } catch (err) {
        next(err);
      }
    });

    auth_router.get("/signout", (req, res, next) => {
      res.cookie("access_token", null, { httpOnly: true, maxAge: 0 });
      res.redirect("/");
    });

    req.app.use("/auth", auth_router);

    // req.app.use((err, req, res, next) => {
    //   res.json({ error: err });
    // });

    next();
  };
};
