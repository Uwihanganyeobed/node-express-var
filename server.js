// CRUD API but improved with:

// User authentication

// Email & Password

// Password hashing with bcryptjs

// Token authentication using JSON Web Token

// Protected routes (only logged-in users can create/update/delete products)

// Clear comments explaining every step

// First install the packages on terminal:

// npm install bcryptjs jsonwebtoken

// IMPORT PACKAGES
import express from "express"
import bcrypt from "bcryptjs"        // used to hash passwords
import jwt from "jsonwebtoken"       // used to generate authentication tokens

// INITIALIZE EXPRESS APP
const app = express()
app.use(express.json()) // allows API to receive JSON data

// SECRET KEY FOR JWT (normally stored in .env)
const SECRET = "mysecretkey"


// ============================
// FAKE DATABASES (ARRAYS)
// ============================

// fake users table
let users = []

// fake products table
let products = [
    { id: 1, name: "Laptop", price: 4000 },
    { id: 2, name: "Phone", price: 5500 }
]

let nextId = 3
let nextUserId = 1



// ============================
// HOME ROUTE
// ============================
app.get("/", (req, res) => {
    res.send("Welcome to my API")
})



// ============================
// USER REGISTER
// ============================

app.post("/register", async (req, res) => {

    const { email, password } = req.body

    // check if user already exists
    const userExists = users.find(u => u.email === email)

    if (userExists) {
        return res.status(400).json({ message: "User already exists" })
    }

    // hash password before saving
    const hashedPassword = await bcrypt.hash(password, 10)

    // create new user
    const newUser = {
        id: nextUserId++,
        email,
        password: hashedPassword
    }

    users.push(newUser)

    res.json({
        message: "User registered successfully",
        user: { id: newUser.id, email: newUser.email }
    })
})



// ============================
// USER LOGIN
// ============================

app.post("/login", async (req, res) => {

    const { email, password } = req.body

    // check if user exists
    const user = users.find(u => u.email === email)

    if (!user) {
        return res.status(404).json({ message: "User not found" })
    }

    // compare password with hashed password
    const validPassword = await bcrypt.compare(password, user.password)

    if (!validPassword) {
        return res.status(401).json({ message: "Invalid password" })
    }

    // create JWT token
    const token = jwt.sign(
        { id: user.id, email: user.email },
        SECRET,
        { expiresIn: "1h" }
    )

    res.json({
        message: "Login successful",
        token
    })
})



// ============================
// AUTH MIDDLEWARE
// ============================

// this function checks if user is logged in
function authenticateToken(req, res, next) {

    const authHeader = req.headers["authorization"]

    if (!authHeader) {
        return res.status(401).json({ message: "Access denied. No token provided." })
    }

    const token = authHeader.split(" ")[1]

    jwt.verify(token, SECRET, (err, user) => {

        if (err) {
            return res.status(403).json({ message: "Invalid token" })
        }

        req.user = user
        next()
    })
}



// ============================
// PRODUCTS CRUD
// ============================


// GET all products (public)
app.get("/products", (req, res) => {
    res.json(products)
})



// CREATE product (protected)
app.post("/products", authenticateToken, (req, res) => {

    const newProduct = {
        id: nextId++,
        name: req.body.name,
        price: req.body.price
    }

    products.push(newProduct)

    res.json({
        message: "Product created",
        data: newProduct
    })
})



// GET single product
app.get("/products/:id", (req, res) => {

    const id = parseInt(req.params.id)

    const product = products.find(p => p.id === id)

    if (!product) {
        return res.status(404).json({ message: "No product found" })
    }

    res.json(product)
})



// UPDATE product (protected)
app.put("/products/:id", authenticateToken, (req, res) => {

    const id = parseInt(req.params.id)

    const product = products.find(p => p.id === id)

    if (!product) {
        return res.status(404).json({ message: "No product found" })
    }

    product.name = req.body.name || product.name
    product.price = req.body.price || product.price

    res.json({
        message: "Product updated",
        data: product
    })
})



// DELETE product (protected)
app.delete("/products/:id", authenticateToken, (req, res) => {

    const id = parseInt(req.params.id)

    const index = products.findIndex(p => p.id === id)

    if (index === -1) {
        return res.status(404).json({ message: "No product found" })
    }

    const deletedProduct = products.splice(index, 1)

    res.json({
        message: "Product deleted",
        data: deletedProduct
    })
})



// ============================
// SERVER
// ============================

app.listen(4000, () => {
    console.log("Server is running on port 4000")
})