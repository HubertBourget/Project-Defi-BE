require("dotenv").config();
const {Web3} = require("web3");
const jwt = require("jsonwebtoken");
const bcrypt = require('bcrypt');
const { MongoClient } = require('mongodb');

const uri = process.env.MONGO_URI;
const client = new MongoClient(uri);
let web3 = new Web3("https://rpc.ankr.com/eth");
const ADDRESS = "0x5460687A450450355722C489877CF6C2ef54374C";
const ABI = require("./ABI.js");
const contract = new web3.eth.Contract(ABI, ADDRESS);

const signNft = async (req, res) => {
    let address = await web3.eth.accounts.recover("Message to sign", req.query.signature)
    var balance = Number(await contract.methods.balanceOf(address).call())
    if (balance > 0) {
        res.json({ hasNft: true, balance: balance })
    } else {
        res.json({ hasNft: false, balance: balance })
    }
}

const getAccessTokenC = async (req, res) => {
    try {
        const { walletAddress } = req.body;
        const user = { walletAddress };
        const accessToken = jwt.sign(user, process.env.JWT_ACCESS_TOKEN_C, { expiresIn: '15m' });
        res.json({ accessToken: accessToken });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

const verifyAccessTokenC = (req, res) => {
    try {
        const { accessTokenC } = req.body;

        // Verify the token using your secret key or public key
        const decodedToken = jwt.verify(accessTokenC, process.env.JWT_ACCESS_TOKEN_C);

        // Check if the token has expired
        const currentTimestamp = Math.floor(Date.now() / 1000);
        if (decodedToken.exp < currentTimestamp) {
        res.json({ valid: false, message: 'Token has expired' });
        } else {
        res.json({ valid: true });
        }
    } catch (error) {
        res.json({ valid: false, message: 'Token verification failed' });
    }
};

const signup = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Connect to MongoDB
        await client.connect();

        // Check if the email already exists in the database
        const db = client.db('db');
        const usersCollection = db.collection('users');
        const existingUser = await usersCollection.findOne({ email: email });

        if (existingUser) {
        // Email already exists, refuse the signup
        return res.status(400).json({ success: false, error: 'Email already exists' });
        }

        // Generate salt and hash the password
        const saltRounds = 10;
        const salt = await bcrypt.genSalt(saltRounds);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Insert the user document into the "users" collection
        await usersCollection.insertOne({
        email: email,
        password: hashedPassword,
        salt: salt,
        });

        res.json({ success: true });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    } finally {
        // Close the MongoDB connection
        await client.close();
    }
};


const getAccessTokenA = async (req, res) => {
    try {
        const { email } = req.body;
        const user = { email };
        const accessToken = jwt.sign(user, process.env.JWT_ACCESS_TOKEN_A, { expiresIn: '90d' });
        res.json({ accessToken: accessToken });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

const verifyAccessTokenA = (req, res) => {
    try {
        const { accessTokenA } = req.body;

        // Verify the token using your secret key or public key
        const decodedToken = jwt.verify(accessTokenA, process.env.JWT_ACCESS_TOKEN_A);

        // Check if the token has expired
        const currentTimestamp = Math.floor(Date.now() / 1000);
        if (decodedToken.exp < currentTimestamp) {
        res.json({ valid: false, message: 'Token has expired' });
        } else {
        res.json({ valid: true });
        }
    } catch (error) {
        res.json({ valid: false, message: 'Token verification failed' });
    }
};

const getAccountDetails = async (req, res) => {
    try {
        // Perform the necessary checks for terms and account details completeness
        const { accessTokenA } = req.body;
        
        // Decrypt the JWT token and access the payload data
        const decodedToken = jwt.verify(accessTokenA, process.env.JWT_ACCESS_TOKEN_A);

        // Access the email value from the decoded token
        const email = decodedToken.email;

        // Connect to MongoDB
        await client.connect();

        // Check if the email exists in the database
        const db = client.db('db');
        const usersCollection = db.collection('users');
        const existingUser = await usersCollection.findOne({ email: email });

        if (!existingUser) {
        // Email does not exist, handle the case appropriately (e.g., redirect to an error page)
        return res.status(403).json({ reason: 'email-not-found' });
        }

        // Check if the user has signed the terms of services
        const termsSigned = existingUser.termsSigned;

        if (!termsSigned) {
        return res.status(403).json({ reason: 'terms-not-signed' });
        }

        // Check if the user's account details are complete
        const accountDetailsComplete = false; // Replace with your logic to check if account details are complete

        if (!accountDetailsComplete) {
        return res.status(403).json({ reason: 'account-details-incomplete' });
        }

        // If all checks pass, the user has access to the normal content
        res.json({ success: true });
    } catch (error) {
        console.error('Error retrieving account details:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
};

const updateTermsSigned = async (req, res) => {
    try {
        const { accessTokenA } = req.body;
        
        // Decrypt the JWT token and access the payload data
        const decodedToken = jwt.verify(accessTokenA, process.env.JWT_ACCESS_TOKEN_A);

        // Access the email value from the decoded token
        const email = decodedToken.email;

        // Connect to MongoDB
        await client.connect();

        // Update the termsSigned field for the user with the specified email
        const db = client.db('db');
        const usersCollection = db.collection('users');
        await usersCollection.updateOne({ email: email }, { $set: { termsSigned: true } });

        res.json({ success: true });
    } catch (error) {
        console.error('Error updating termsSigned field:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    } finally {
        // Close the MongoDB connection
        await client.close();
    }
};

module.exports = {
    signNft,
    signup,
    getAccessTokenC,
    verifyAccessTokenC,
    getAccessTokenA,
    verifyAccessTokenA,
    getAccountDetails,
    updateTermsSigned,
};