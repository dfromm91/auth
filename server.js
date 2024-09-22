require("dotenv").config(); 
const express = require("express");
const mongoose = require("mongoose");
const passport = require("passport");
const jwt = require("jsonwebtoken");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const path = require("path"); // Import path module
const User = require("./models/User");
const cors = require("cors");

const app = express();

// CORS configuration
app.use(
  cors({
    origin: ["https://bananagrams.onrender.com", "http://localhost:5173"], 
    credentials: true, // Allow credentials like cookies/sessions
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
        console.log("Google OAuth Profile Data:", profile);

        // Check if user already exists in DB
        let user = await User.findOne({ googleId: profile.id });
        if (user) {
          console.log("User found in DB:", user);
          return done(null, user);
        }

        // If not, create a new user
        user = new User({
          googleId: profile.id,
          displayName: profile.displayName,
          email: profile.emails[0].value,
        });

        await user.save();
        console.log("New user created:", user);
        return done(null, user);
      } catch (err) {
        console.error("Error in OAuth callback:", err);
        return done(err, false);
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
      console.log("JWT payload:", jwt_payload);
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
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"], session: false })
);
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/", session: false }),
  (req, res) => {
    // Generate JWT here and send it to the client
    const token = jwt.sign(
      { id: req.user.id },
      process.env.JWT_SECRET || 'your_jwt_secret_key',
      { expiresIn: '1d' }
    );
    res.redirect(`https://bananagrams.onrender.com/auth/callback?token=${token}`);
  }
);


// Logout route (Token-based approach doesn't require server-side session destruction)
app.get("/logout", (req, res) => {
  res.json({ message: "Logged out successfully." });
});

// Endpoint to check authentication status
app.get(
  "/auth/google/status",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    if (req.user) {
      console.log("User is authenticated:", req.user);
      res.json({ isAuthenticated: true, user: req.user });
    } else {
      console.log("User is not authenticated");
      res.json({ isAuthenticated: false });
    }
  }
);

// Default home route
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// Leaderboard route (Protected with JWT)
app.get("/leaderboard", async (req, res) => {
  try {
    const leaderboard = await User.find().sort({ wins: -1 }).limit(10);
    console.log("Leaderboard fetched:", leaderboard);
    res.json(leaderboard);
  } catch (err) {
    console.error("Error fetching leaderboard:", err);
    res.status(500).json({ error: "Failed to fetch leaderboard" });
  }
});

// Update wins route (Protected with JWT)
app.post(
  "/update-wins",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    const userId = req.user.id;
    console.log("Updating wins for user ID:", userId);
    try {
      const user = await User.findById(userId);
      if (!user) {
        console.log("User not found:", userId);
        return res.status(404).json({ success: false, message: "User not found" });
      }

      user.wins += 1; // Increment the user's wins
      await user.save();
      console.log("Wins incremented for user:", user);
      return res.json({ success: true, message: "Wins incremented", wins: user.wins });
    } catch (error) {
      console.error("Error updating wins:", error);
      return res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

// Update losses route (Protected with JWT)
app.post(
  "/update-losses",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    const userId = req.user.id;
    console.log("Updating losses for user ID:", userId);
    try {
      const user = await User.findById(userId);
      if (!user) {
        console.log("User not found:", userId);
        return res.status(404).json({ success: false, message: "User not found" });
      }

      user.losses += 1; 
      await user.save();
      console.log("Losses incremented for user:", user);
      return res.json({ success: true, message: "Losses incremented", losses: user.losses });
    } catch (error) {
      console.error("Error updating losses:", error);
      return res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

// Fetch user's profile by Google ID (Protected with JWT)
app.get(
  "/profile/:googleId",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    console.log("Fetching profile for googleId:", req.params.googleId);
    try {
      const user = await User.findOne({ googleId: req.params.googleId });
      if (!user) {
        console.log("User not found:", req.params.googleId);
        return res.status(404).json({ message: "User not found" });
      }
      console.log("User profile fetched:", user);
      res.json({ wins: user.wins, losses: user.losses });
    } catch (error) {
      console.error("Error fetching user stats:", error);
      res.status(500).json({ message: "Server error" });
    }
  }
);
