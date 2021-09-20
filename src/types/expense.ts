import { Document } from "mongoose";

export interface IExpense extends Document {
  name: string;
  cost: number;
  userId: string;
}
