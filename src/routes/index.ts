import { Router } from "express";
import {
  addExpense,
  deleteExpense,
  getExpenses,
  updateExpense,
} from "../controllers/expenses";
import * as userController from "../controllers/users/index";

const router: Router = Router();

router.get("/expenses", getExpenses);

router.post("/add-expense", addExpense);

router.put("/edit-expense/:id", updateExpense);

router.delete("/delete-expense/:id", deleteExpense);

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
