import express, { Express } from "express";
import mongoose from "mongoose";
import cors from "cors";
import routes from "./routes";
import passport from "passport";
import { MONGODB_URI, SESSION_SECRET } from "./utils/secrets";

const app: Express = express();

const PORT: string | number = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());
app.use(passport.initialize());
app.use(passport.session());
app.use(routes);
const options = { useNewUrlParser: true, useUnifiedTopology: true };

mongoose.set("useFindAndModify", false);

mongoose
  .connect(MONGODB_URI ?? "", options)
  .then(() =>
    app.listen(PORT, () =>
      console.log(`Server running on http://localhost:${PORT}`)
    )
  )
  .catch((error) => {
    console.log(
      `MongoDB connection error. Please make sure MongoDB is running. ${error}`
    );
    throw error;
  });

export default app;
