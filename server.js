require("dotenv").config(); // Ensure this is at the top
const express = require("express");
const mongoose = require("mongoose");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const session = require("express-session");
const path = require("path");
const User = require("./models/User");
const cors = require("cors");
const MongoStore = require("connect-mongo"); // Add this for MongoDB session storage

const app = express();

// Express session middleware using connect-mongo
app.use(
  session({
    secret: process.env.SESSION_SECRET || "your_secret_key", // Use a secure secret
    resave: false,
    saveUninitialized: false, // Only create session when necessary
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI, // Reuse MongoDB connection URI
      collectionName: "sessions", // MongoDB collection for sessions
    }),
    cookie: {
      sameSite: "None", // Use 'None' for cross-origin requests
      secure: true, // Set secure cookies only in production
      maxAge: 1000 * 60 * 60 * 24, // 1 day expiration
    },
  })
);
app.use((req, res, next) => {
  if (req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect(['https://', req.get('Host'), req.url].join(''));
  }
  next();
});

app.use(express.json()); // This will parse JSON request bodies

// Initialize Passport and restore authentication state from the session
app.use(passport.initialize());
app.use(passport.session());

// Enable CORS (Allow requests from the React app)
app.use(cors({
  origin: "https://bananagrams.onrender.com", // Your React frontend
  methods: ["GET", "POST"],
  credentials: true, // Allow credentials like cookies/sessions
}));


// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, "public")));

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("connected to db!");
    app.listen(3001, () => {
      // Change the server port to 3001
      console.log("Server running on port 3001");
    });
  })
  .catch(() => {
    console.log("connection failed");
  });

// Passport configuration
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Check if user already exists in DB
        let user = await User.findOne({ googleId: profile.id });

        if (user) {
          return done(null, user);
        }

        // If not, create a new user
        user = new User({
          googleId: profile.id,
          displayName: profile.displayName,
          email: profile.emails[0].value,
        });

        await user.save();
        done(null, user);
      } catch (err) {
        done(err, false);
      }
    }
  )
);

// Serialize user to the session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user from the session
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Routes

// Default home route
app.get("/", (req, res) => {
  if (req.user) {
    res.send(`Hello ${req.user.displayName}, you are logged in!`);
  } else {
    res.sendFile(path.join(__dirname, "public", "login.html"));
  }
});

// Google OAuth routes
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    // Successful authentication, redirect to the game setup in the React app
    console.log('success')
    res.redirect(process.env.CLIENT_URL || "http://localhost:5173/");
  }
);

// Logout route on the server
app.get("/logout", (req, res) => {
  res.setHeader(
    "Set-Cookie",
    "connect.sid=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=None; Secure"
  );
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    req.session.destroy(); // Destroy session on the server
    res.redirect("/"); // Redirect to homepage after logout
  });
});

// Endpoint to check authentication status
app.get("/auth/google/status", (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ isAuthenticated: true, user: req.user });
    console.log('you are in');
  } else {
    res.json({ isAuthenticated: false });
    console.log('nope')
  }
});

app.get("/leaderboard", async (req, res) => {
  try {
    const leaderboard = await User.find().sort({ wins: -1 }).limit(10);
    res.json(leaderboard);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch leaderboard" });
  }
});

// Add this new route to handle win updates
app.post("/update-wins", async (req, res) => {
  const { googleId } = req.body;
  console.log(googleId);
  try {
    const user = await User.findOne({ googleId });

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    user.wins += 1; // Increment the user's wins
    await user.save();

    return res.json({
      success: true,
      message: "Wins incremented",
      wins: user.wins,
    });
  } catch (error) {
    console.error("Error updating wins:", error);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/update-losses", async (req, res) => {
  const { googleId } = req.body;

  try {
    const user = await User.findOne({ googleId });

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    user.losses += 1; // Increment the player's losses
    await user.save();

    return res.json({
      success: true,
      message: "Losses incremented",
      losses: user.losses,
    });
  } catch (error) {
    console.error("Error updating losses:", error);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// Route to get user's wins and losses using googleId
app.get("/profile/:googleId", async (req, res) => {
  try {
    const user = await User.findOne({ googleId: req.params.googleId });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json({ wins: user.wins, losses: user.losses });
  } catch (error) {
    console.error("Error fetching user stats:", error);
    res.status(500).json({ message: "Server error" });
  }
});
