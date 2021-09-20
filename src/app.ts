import express, { Express } from "express";
import mongoose from "mongoose";
import cors from "cors";
import routes from "./routes";
import { MONGODB_URI, SESSION_SECRET } from "./utils/secrets";

const app: Express = express();

const PORT: string | number = process.env.PORT || 4000;

app.use(cors());
app.use(routes);

// const uri: string = `mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASSWORD}@clustertodo.raz9g.mongodb.net/${process.env.MONGO_DB}?retryWrites=true&w=majority`;
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
