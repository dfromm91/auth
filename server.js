require("dotenv").config(); // Ensure this is at the top
const express = require("express");
const mongoose = require("mongoose");
const passport = require("passport");
const jwt = require("jsonwebtoken");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const User = require("./models/User");
const cors = require("cors");

const app = express();

// CORS configuration
app.use(
  cors({
    origin: ["https://bananagrams.onrender.com", "http://localhost:5173"], // Your React frontend
    credentials: true, // Allow credentials
    preflightContinue: false,
  })
);

app.use(express.json()); // Parse JSON request bodies

// Initialize Passport
app.use(passport.initialize());

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("Connected to DB!");
    app.listen(3001, () => {
      console.log("Server running on port 3001");
    });
  })
  .catch(() => {
    console.log("MongoDB connection failed");
  });

// Passport configuration for Google OAuth
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
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

// JWT Strategy for protecting routes
const opts = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: process.env.JWT_SECRET || "your_jwt_secret_key",
};

passport.use(
  new JwtStrategy(opts, async (jwt_payload, done) => {
    try {
      const user = await User.findById(jwt_payload.id);
      if (user) {
        return done(null, user);
      } else {
        return done(null, false);
      }
    } catch (err) {
      return done(err, false);
    }
  })
);

// Google OAuth routes
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    const token = jwt.sign(
      { id: req.user.id },
      process.env.JWT_SECRET || "your_jwt_secret_key",
      { expiresIn: "1d" } // Token expires in 1 day
    );

    // Send the token to the client, you can also redirect with the token if needed
    res.json({ token });
  }
);

// Logout route (Token-based approach doesn't require server-side session destruction)
app.get("/logout", (req, res) => {
  res.json({ message: "Logged out successfully." });
});

// Check authentication status (now using JWT verification)
app.get("/auth/google/status", passport.authenticate('jwt', { session: false }), (req, res) => {
  if (req.user) {
    res.json({ isAuthenticated: true, user: req.user });
  } else {
    res.json({ isAuthenticated: false });
  }
});

// Default home route
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// Protected leaderboard route (using JWT to verify user)
app.get("/leaderboard", passport.authenticate('jwt', { session: false }), async (req, res) => {
  try {
    const leaderboard = await User.find().sort({ wins: -1 }).limit(10);
    res.json(leaderboard);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch leaderboard" });
  }
});

// Update wins route (Protected with JWT)
app.post("/update-wins", passport.authenticate('jwt', { session: false }), async (req, res) => {
  const { googleId } = req.body;
  try {
    const user = await User.findOne({ googleId });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    user.wins += 1; // Increment the user's wins
    await user.save();
    return res.json({ success: true, message: "Wins incremented", wins: user.wins });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// Update losses route (Protected with JWT)
app.post("/update-losses", passport.authenticate('jwt', { session: false }), async (req, res) => {
  const { googleId } = req.body;
  try {
    const user = await User.findOne({ googleId });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    user.losses += 1; // Increment the user's losses
    await user.save();
    return res.json({ success: true, message: "Losses incremented", losses: user.losses });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// Fetch user's profile by Google ID (Protected with JWT)
app.get("/profile/:googleId", passport.authenticate('jwt', { session: false }), async (req, res) => {
  try {
    const user = await User.findOne({ googleId: req.params.googleId });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json({ wins: user.wins, losses: user.losses });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});
