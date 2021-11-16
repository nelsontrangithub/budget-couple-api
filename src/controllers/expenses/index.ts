import { Response, Request } from "express";
import { IExpense } from "./../../types/expense";
import Expense from "../../models/expense";

const getExpenses = async (req: Request, res: Response): Promise<void> => {
  try {
    const expenses: IExpense[] = await Expense.find({
      userId: req.currentUser.id,
    });
    res.status(200).json({ expenses });
  } catch (error) {
    throw error;
  }
};

const addExpense = async (req: Request, res: Response): Promise<void> => {
  try {
    const body = req.body as Pick<IExpense, "name" | "cost">;
    const expense: IExpense = new Expense({
      name: body.name,
      cost: body.cost,
      userId: req.currentUser.id,
    });

    const newExpense: IExpense = await expense.save();
    const allExpenses: IExpense[] = await Expense.find({
      userId: req.currentUser.id,
    });

    res.status(201).json({
      message: "Expense added",
      expense: newExpense,
      expenses: allExpenses,
    });
  } catch (error) {
    throw error;
  }
};

const updateExpense = async (req: Request, res: Response): Promise<void> => {
  try {
    const {
      params: { id },
      body,
    } = req;
    const updateExpense: IExpense | null = await Expense.findByIdAndUpdate(
      { _id: id },
      body
    );
    const allExpenses: IExpense[] = await Expense.find({
      userId: req.currentUser.id,
    });
    res.status(200).json({
      message: "Expense updated",
      expense: updateExpense,
      expenses: allExpenses,
    });
  } catch (error) {
    throw error;
  }
};

const deleteExpense = async (req: Request, res: Response): Promise<void> => {
  try {
    const deletedExpense: IExpense | null = await Expense.findByIdAndRemove(
      req.params.id
    );
    const allExpenses: IExpense[] = await Expense.find({
      userId: req.currentUser.id,
    });
    res.status(200).json({
      message: "Expense deleted",
      expense: deletedExpense,
      expenses: allExpenses,
    });
  } catch (error) {
    throw error;
  }
};

export { getExpenses, addExpense, updateExpense, deleteExpense };
