import { Router } from "express";
import {
  addExpense,
  deleteExpense,
  getExpenses,
  updateExpense,
} from "../controllers/expenses";
import * as userController from "../controllers/users/index";
import * as passportConfig from "../config/passport";

const router: Router = Router();

router.get("/expenses/", passportConfig.isAuthenticated, getExpenses);
router.post("/add-expense/", passportConfig.isAuthenticated, addExpense);
router.put("/edit-expense/:id", passportConfig.isAuthenticated, updateExpense);
router.delete(
  "/delete-expense/:id",
  passportConfig.isAuthenticated,
  deleteExpense
);

router.get("/login", userController.getLogin);
router.post("/login", userController.postLogin);
router.get("/logout", userController.logout);
router.get("/forgot", userController.getForgot);
router.get("/reset/:token", userController.getReset);
router.post("/reset/:token", userController.postReset);
router.get("/signup", userController.getSignup);
router.post("/signup", userController.postSignup);
router.post("/update-password", userController.postUpdatePassword);

export default router;
