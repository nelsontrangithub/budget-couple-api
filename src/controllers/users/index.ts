import async from "async";
import { User, UserDocument, AuthToken } from "../../types/user";
import { Request, Response, NextFunction } from "express";
import { WriteError } from "mongodb";
import { check, sanitize, validationResult } from "express-validator";
import "../../config/passport";
import { NativeError } from "mongoose";
import { IExpense } from "./../../types/expense";
import Expense from "../../models/expense";
import jwt from "jsonwebtoken";
import { SESSION_SECRET, REFRESH_SECRET } from "../../utils/secrets";

const refreshTokens: string[] = [];

const generateAccessToken = (user: Pick<UserDocument, "email" | "id">) =>
  jwt.sign(user, SESSION_SECRET, { expiresIn: "15m" });

/**
 * Login page.
 * @route GET /login
 */
export const getLogin = (req: Request, res: Response): void => {
  if (req.user) res.json({ user: req?.user });
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(401).json({ error: "validation errors" });
  }

  res.json({ msg: "logged in" });
};

export const getUser = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const user = await User.findById(req.user ?? "").select("-password");
    res.status(200).json(user);
  } catch (err) {
    res.status(404).json({ err: "error signing in" });
    return next(err);
  }
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
    res.status(401).json({ error: "validation errors" });
    return next(errors);
  }

  const user = await User.findOne({ email: req.body.email });

  if (!user) {
    res.status(401).json({ error: "email not found" });
    return next(errors);
  }

  user.comparePassword(req.body.password, (err: Error, isMatch: boolean) => {
    if (err) {
      res.status(401).json({ error: "bad password" });
      return next(errors);
    }

    if (isMatch) {
      const token = generateAccessToken({ email: user.email, id: user.id });

      const refreshToken = jwt.sign(
        { email: user.email, id: user.id },
        REFRESH_SECRET
      );

      refreshTokens.push(refreshToken);

      req.logIn(user, async (err) => {
        if (err) return next(err);
        const expenses: IExpense[] = await Expense.find({ userId: user.id });
        res
          .status(200)
          .json({ user, expenses, msg: "success", token, refreshToken });
      });
    } else {
      res.status(401).json({ error: "bad password" });
      return next(errors);
    }
  });
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
  if (req.user) return res.redirect("/");
  res.json({ msg: "getting sign up" });
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
    profile: {
      income: {
        you: 80000,
        partner: 80000,
      },
    },
  });

  User.findOne(
    { email: req.body.email },
    (err: NativeError, existingUser: UserDocument) => {
      if (err) return next(err);

      if (existingUser) {
        res
          .status(403)
          .json({ error: "Account with that email address already exists." });
      }

      user.save((err) => {
        if (err) return next(err);

        req.logIn(user, (err) => {
          if (err) return next(err);

          res.status(200).json({ user, msg: "Account created successfully" });
        });
      });
    }
  );
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
    res.status(400).json({ error: "validation error" });
    return next(errors);
  }

  const user = req.user as UserDocument;
  User.findById(user.id, (err: NativeError, user: UserDocument) => {
    if (err) return next(err);

    user.email = req.body.email || "";
    user.profile.name = req.body.name || "";
    user.save((err) => {
      if (err) return next(err);

      res.status(200).json({ msg: "Profile information has been updated." });
    });
  });
};

/**
 * Update profile income information.
 * @route POST /user/incomes
 */
export const postUpdateProfileIncome = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  await check("you", "Please enter a valid number.").isNumeric().run(req);
  await check("partner", "Please enter a valid number").isNumeric().run(req);

  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    res.status(400).json({ error: "validation error" });
    return next(errors);
  }

  const userId = req.user as UserDocument;
  User.findById(userId, (err: NativeError, user: UserDocument) => {
    if (err) return next(err);
    user.profile.income.you = req.body.you;
    user.profile.income.partner = req.body.partner;
    user.markModified("profile");
    user.save((err) => {
      if (err) return next(err);
      res.status(200).json({ msg: "Profile information has been updated." });
    });
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
    res.status(400).json({ error: "validation error" });
    return next(errors);
  }

  if (!req.user) {
    res.status(400).json({ error: "not logged in" });
    return next(errors);
  }

  const user = req.user as UserDocument;

  User.findById(user.id, (err: NativeError, user: UserDocument) => {
    if (err) {
      return next(err);
    }
    user.password = req.body.password;
    user.save((err) => {
      if (err) return next(err);
      res.status(200).json({ msg: "Password has been changed." });
    });
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
    if (err) return next(err);
    req.logout();
    res.status(200).json({ msg: "Your account has been deleted." });
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
    if (err) return next(err);
    user[provider] = undefined;
    user.tokens = user.tokens.filter(
      (token: AuthToken) => token.kind !== provider
    );
    user.save((err: WriteError) => {
      if (err) return next(err);
      res.status(200).json({ msg: `${provider} account has been unlinked.` });
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
      if (err) return next(err);
      if (!user) {
        res.status(400).json({
          msg: "Password reset token is invalid or has expired.",
        });
        return next(err);
      }
      res.status(200);
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
    res.status(400).json({ error: "validation error" });
    return next(errors);
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
              res.status(400).json({
                error: "Password reset token is invalid or has expired.",
              });
              return next(err);
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
              res.status(200);
            });
          });
      },
    ],
    (err) => {
      if (err) next(err);
      res.status(400);
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
  res.status(200).json({ msg: "getting sign up" });
};

export const refreshToken = (
  req: Request,
  res: Response
): Response<any, Record<string, any>> | undefined => {
  const refreshToken = req.body.token;
  if (refreshToken == null) return res.sendStatus(401);
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
  jwt.verify(refreshToken, REFRESH_SECRET, (decoded: any) => {
    const user = decoded as Pick<UserDocument, "email" | "id">;

    if (!user.email || !user.id) {
      return res.sendStatus(403);
    }

    const token = generateAccessToken(user);
    res.json({ token: token });
  });
};
