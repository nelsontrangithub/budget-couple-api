import { IExpense } from "./../types/expense";
import { model, Schema } from "mongoose";

const expenseSchema: Schema = new Schema(
  {
    name: {
      type: String,
      required: true,
    },
    cost: {
      type: Number,
      required: true,
    },
    userId: {
      type: String,
      required: true,
    },
  },
  { timestamps: true }
);

export default model<IExpense>("Expense", expenseSchema);
