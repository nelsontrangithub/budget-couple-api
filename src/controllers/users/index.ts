import async from "async";
import passport from "passport";
import { User, UserDocument, AuthToken } from "../../types/user";
import { Request, Response, NextFunction } from "express";
import { IVerifyOptions } from "passport-local";
import { WriteError } from "mongodb";
import { check, sanitize, validationResult } from "express-validator";
import "../../config/passport";
import { CallbackError, NativeError } from "mongoose";

/**
 * Login page.
 * @route GET /login
 */
export const getLogin = (req: Request, res: Response): void => {
  if (req.user) {
    res.json({ user: req?.user });
  }
  res.json({ message: "logged in" });
};

/**
 * Sign in using email and password.
 * @route POST /login
 */
export const postLogin = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  await check("email", "Email is not valid").isEmail().run(req);
  await check("password", "Password cannot be blank")
    .isLength({ min: 1 })
    .run(req);
  await sanitize("email").normalizeEmail({ gmail_remove_dots: false }).run(req);

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // req.flash("errors", errors.array());
    res.status(401).json({ error: "validation errors" });
    return next(errors);
  }

  passport.authenticate(
    "local",
    (err: Error, user: UserDocument, info: IVerifyOptions) => {
      if (err) {
        return next(err);
      }
      if (!user) {
        res.status(401).json({ err: "error signing in" });
        return next(err);
      }
      req.logIn(user, (err) => {
        if (err) {
          return next(err);
        }
        res.json({ message: "success" });
      });
    }
  )(req, res, next);
};

/**
 * Log out.
 * @route GET /logout
 */
export const logout = (req: Request, res: Response): void => {
  req.logout();
  res.redirect("/");
};

/**
 * Signup page.
 * @route GET /signup
 */
export const getSignup = (req: Request, res: Response): void => {
  if (req.user) {
    return res.redirect("/");
  }
  res.json({ message: "getting sign up" });
};

/**
 * Create a new local account.
 * @route POST /signup
 */
export const postSignup = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  await check("email", "Email is not valid").isEmail().run(req);
  await check("password", "Password must be at least 4 characters long")
    .isLength({ min: 4 })
    .run(req);
  await check("confirmPassword", "Passwords do not match")
    .equals(req.body.password)
    .run(req);
  await sanitize("email").normalizeEmail({ gmail_remove_dots: false }).run(req);

  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    res.status(403).json({ error: "validation error" });
    return next(errors);
  }

  const user = new User({
    email: req.body.email,
    password: req.body.password,
  });

  User.findOne(
    { email: req.body.email },
    (err: NativeError, existingUser: UserDocument) => {
      if (err) {
        return next(err);
      }
      if (existingUser) {
        res
          .status(403)
          .json({ error: "Account with that email address already exists." });
      }
      user.save((err) => {
        if (err) {
          return next(err);
        }
        req.logIn(user, (err) => {
          if (err) {
            return next(err);
          }
          res.status(200).json({ message: "Account created successfully" });
        });
      });
    }
  );
};

/**
 * Profile page.
 * @route GET /account
 */
export const getAccount = (req: Request, res: Response): void => {
  res.json({ message: "getting account" });
};

/**
 * Update profile information.
 * @route POST /account/profile
 */
export const postUpdateProfile = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  await check("email", "Please enter a valid email address.")
    .isEmail()
    .run(req);
  await sanitize("email").normalizeEmail({ gmail_remove_dots: false }).run(req);

  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    // req.flash("errors", errors.array());
    return res.redirect("/account");
  }

  const user = req.user as UserDocument;
  User.findById(user.id, (err: NativeError, user: UserDocument) => {
    if (err) return next(err);

    user.email = req.body.email || "";
    user.profile.name = req.body.name || "";
    // user.save((err: WriteError & CallbackError) => {
    //   if (err) {
    //     if (err.code === 11000) {
    //       // req.flash("errors", {
    //       //   msg: "The email address you have entered is already associated with an account.",
    //       // });
    //       return res.redirect("/account");
    //     }
    //     return next(err);
    //   }
    //   // req.flash("success", { msg: "Profile information has been updated." });
    //   res.redirect("/account");
    // });
  });
};

/**
 * Update current password.
 * @route POST /account/password
 */
export const postUpdatePassword = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  await check("password", "Password must be at least 4 characters long")
    .isLength({ min: 4 })
    .run(req);
  await check("confirmPassword", "Passwords do not match")
    .equals(req.body.password)
    .run(req);

  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    // req.flash("errors", errors.array());
    return res.redirect("/account");
  }

  const user = req.user as UserDocument;
  User.findById(user.id, (err: NativeError, user: UserDocument) => {
    if (err) {
      return next(err);
    }
    user.password = req.body.password;
    // user.save((err: WriteError & CallbackError) => {
    //   if (err) {
    //     return next(err);
    //   }
    //   req.flash("success", { msg: "Password has been changed." });
    //   res.redirect("/account");
    // });
  });
};

/**
 * Delete user account.
 * @route POST /account/delete
 */
export const postDeleteAccount = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const user = req.user as UserDocument;
  User.remove({ _id: user.id }, (err) => {
    if (err) {
      return next(err);
    }
    req.logout();
    // req.flash("info", { msg: "Your account has been deleted." });
    res.redirect("/");
  });
};

/**
 * Unlink OAuth provider.
 * @route GET /account/unlink/:provider
 */
export const getOauthUnlink = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const provider = req.params.provider;
  const user = req.user as UserDocument;
  User.findById(user.id, (err: NativeError, user: any) => {
    if (err) {
      return next(err);
    }
    user[provider] = undefined;
    user.tokens = user.tokens.filter(
      (token: AuthToken) => token.kind !== provider
    );
    user.save((err: WriteError) => {
      if (err) {
        return next(err);
      }
      // req.flash("info", { msg: `${provider} account has been unlinked.` });
      res.redirect("/account");
    });
  });
};

/**
 * Reset Password page.
 * @route GET /reset/:token
 */
export const getReset = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  if (req.isAuthenticated()) {
    return res.redirect("/");
  }
  User.findOne({ passwordResetToken: req.params.token })
    .where("passwordResetExpires")
    .gt(Date.now())
    .exec((err, user) => {
      if (err) {
        return next(err);
      }
      if (!user) {
        // req.flash("errors", {
        //   msg: "Password reset token is invalid or has expired.",
        // });
        return res.redirect("/forgot");
      }
      res.json({ message: "forgot password" });
    });
};

/**
 * Process the reset password request.
 * @route POST /reset/:token
 */
export const postReset = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  await check("password", "Password must be at least 4 characters long.")
    .isLength({ min: 4 })
    .run(req);
  await check("confirm", "Passwords must match.")
    .equals(req.body.password)
    .run(req);

  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    // req.flash("errors", errors.array());
    return res.redirect("back");
  }

  async.waterfall(
    [
      function resetPassword(done: (err: any, user: UserDocument) => void) {
        User.findOne({ passwordResetToken: req.params.token })
          .where("passwordResetExpires")
          .gt(Date.now())
          .exec((err, user: any) => {
            if (err) {
              return next(err);
            }
            if (!user) {
              // req.flash("errors", {
              //   msg: "Password reset token is invalid or has expired.",
              // });
              return res.redirect("back");
            }
            user.password = req.body.password;
            user.passwordResetToken = undefined;
            user.passwordResetExpires = undefined;
            user.save((err: WriteError) => {
              if (err) {
                return next(err);
              }
              req.logIn(user, (err) => {
                done(err, user);
              });
            });
          });
      },
    ],
    (err) => {
      if (err) {
        return next(err);
      }
      res.redirect("/");
    }
  );
};

/**
 * Forgot Password page.
 * @route GET /forgot
 */
export const getForgot = (req: Request, res: Response): void => {
  if (req.isAuthenticated()) {
    return res.redirect("/");
  }
  res.json({ message: "getting sign up" });
};
