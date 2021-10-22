import express, { Express } from "express";
import session from "express-session";
import mongoose from "mongoose";
import cors from "cors";
import mongo from "connect-mongo";
import routes from "./routes";
import passport from "passport";
import { MONGODB_URI, SESSION_SECRET } from "./utils/secrets";

const MongoStore = mongo(session);

const app: Express = express();
const mongoUrl = MONGODB_URI ?? "";
const PORT: string | number = process.env.PORT || 4000;
const originURL: string = process.env.ORIGIN_URL || "http://localhost:3001";

app.use(
  cors({
    credentials: true,
    origin: originURL,
    exposedHeaders: ["set-cookie"],
  })
);
app.use(express.json());
app.use(
  session({
    resave: true,
    saveUninitialized: true,
    secret: SESSION_SECRET ?? "",
    store: new MongoStore({
      url: mongoUrl,
      autoReconnect: true,
    }),
    cookie: {
      maxAge: 1000 * 30,
      httpOnly: false,
      // secure: true,
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());

app.use((req, res, next) => {
  res.locals.user = req.user;
  next();
});

app.use((req, res, next) => {
  console.log(req.session, "session");
  console.log(req.user, "user");
  console.log(req.cookies, "cookies");
  next();
});

app.use(routes);

const options = { useNewUrlParser: true, useUnifiedTopology: true };

mongoose.set("useFindAndModify", false);

mongoose
  .connect(mongoUrl ?? "", options)
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
