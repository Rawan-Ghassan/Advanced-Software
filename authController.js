const con = require("../config/database");
const bcrypt = require("bcryptjs");
const axios = require("axios");
const jwt = require("jsonwebtoken");
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET;

// User Sign-up
exports.signup = async (req, res) => {
  const { name, email, password, telephone } = req.body;

  if (!name || !email || !password || !telephone) {
    return res.status(400).json({ msg: "Please fill in all fields" });
  }

  try {
    const [existingUser] = await con.promise().query("SELECT * FROM users WHERE email = ?", [email]);

    if (existingUser.length > 0) {
      return res.status(409).json({ msg: "User already exists" });
    }

   
    const userIP = req.ip;
    let address = 'Unknown';

    try {
      const response = await axios.get(`https://api.ipgeolocation.io/ipgeo?apiKey=d184d7782ea44cddb96cbdb87f7c7c9e&ip=${userIP}`);
      const { city, latitude, longitude } = response.data;
      if (city && latitude && longitude) {
        address = `${city} (${latitude}, ${longitude})`;
      }
    } catch (error) {
      console.error("Error fetching location from IP:", error.message);
    }

   
    const hashedPassword = await bcrypt.hash(password, 10);

  
    const sql = "INSERT INTO users (name, email, password, telephone, address) VALUES (?, ?, ?, ?, ?)";
    await con.promise().query(sql, [name, email, hashedPassword, telephone, address]);

    res.status(201).json({ msg: "User registered successfully", address: address });

  } catch (error) {
    console.error("Error during signup process:", error.message);
    res.status(500).json({ msg: "Server error during signup" });
  }
};

// User Sign-in
exports.signin = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ msg: "Please fill in all fields" });
  }

  try {
   
    const [result] = await con.promise().query("SELECT * FROM users WHERE email = ?", [email]);

    if (result.length === 0) {
      return res.status(400).json({ msg: "Invalid email or password" });
    }

    const user = result[0];

    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ msg: "Invalid email or password" });
    }

   
    const token = jwt.sign(
      { id: user.userID, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(200).json({
      msg: "Sign-in successful",
      token,
    });
  } catch (error) {
    console.error("Error during signin process:", error.message);
    res.status(500).json({ msg: "Server error during signin" });
  }
};
