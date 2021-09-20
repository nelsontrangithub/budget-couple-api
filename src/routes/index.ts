import { Router } from "express";
import {
  addExpense,
  deleteExpense,
  getExpenses,
  updateExpense,
} from "../controllers/expenses";

const router: Router = Router();

router.get("/expenses", getExpenses);

router.post("/add-expense", addExpense);

router.put("/edit-expense/:id", updateExpense);

router.delete("/delete-expense/:id", deleteExpense);

export default router;
