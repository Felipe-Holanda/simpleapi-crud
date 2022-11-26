import express from "express";
import users from "./database";
import { hash, compare } from "bcryptjs";
import { v4 as uuidv4 } from "uuid";
import jwt from "jsonwebtoken";
import 'dotenv/config';

const app = express()
app.use(express.json())

//Middlewares
function verifyRegisterMiddleware(req, res, next) {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(406).json({ message: "Required fields are incomplete." });
    const user = users.find(user => user.email === email);
    if (user) return res.status(409).json({ message: "User already exists" });
    return next()
}

async function verifyLoginMiddleware(req, res, next) {
    const user = users.find(user => user.email === req.body.email);
    if (!req.body.email || !req.body.password) return res.status(401).json({ message: "Missing fields." })
    if (!user) return res.status(401).json({ message: "Wrong email or password." })
    const passwordHash = compare(req.body.password, user.password)
    if (!passwordHash) return res.status(401).json({ message: "Wrong email or password." })
    return next()
}

function verifyTokenMiddleware(req, res, next) {
    const token = req.headers.authorization ? req.headers.authorization.split(" ")[1] : false
    if (!token) return res.status(401).json({ message: "Missing authorization headers" })
    try { jwt.verify(token, process.env.SECRET_KEY) } catch { return res.status(401).json({ message: "Invalid token." }) }
    const { uuid } = jwt.verify(token, process.env.SECRET_KEY)
    req.body.uuid = uuid;
    return next()
}

function verifyUuidRequested(req, res, next) {
    const token = req.headers.authorization ? req.headers.authorization.split(" ")[1] : false
    if (!token) return res.status(401).json({ message: "Missing authorization headers." })
    try { jwt.verify(token, process.env.SECRET_KEY) } catch { res.status(401).json({ message: "Invalid token." }) }
    const RequestID = req.params.uuid ? req.params.uuid : false
    if (!RequestID) return res.status(400).json({ message: "Missing user target uuid param." })
    const { uuid } = jwt.verify(token, process.env.SECRET_KEY)
    const user = users.find(user => user.uuid === uuid)
    if (!user) return res.status(204).json()
    if (user.isAdm) {
        req.body.token = token
        req.body.uuid = RequestID
        return next()
    } else {
        req.body.uuid = uuid
        if (user.uuid !== RequestID) return res.status(403).json({ message: "Request denied due absence of privileges." })
        return next()
    }
}

//Services
async function registerService(body) {
    const { password, isAdm } = body;
    const hashPassword = await hash(password, 10);
    const user = { ...body, password: hashPassword, uuid: uuidv4(), createdOn: new Date(), updatedOn: new Date(), isAdm: isAdm === true ? true : false }
    users.push(user);
    return { status: 201, message: { ...user, password: undefined } }
}

async function loginService(body) {
    const user = users.find(user => user.email === body.email)
    const passwordHash = await compare(body.password, user.password)
    if (!user || !passwordHash) return { status: 401, message: { message: "Wrong email or password." } }
    const token = jwt.sign({ uuid: user.uuid }, process.env.SECRET_KEY, { expiresIn: "24h" })
    return { status: 200, message: { token } }
}

function listUsersService(body) {
    const user = users.find(user => user.uuid === body.uuid)
    if (!user) return { status: 400, message: { message: "Invalid token." } }
    const clients = []
    users.forEach(el => clients.push({ ...el, password: undefined }))
    return user.isAdm ? { status: 200, message: clients } : { status: 403, message: { message: "Request denied due absence of privileges." } }
}

function displayProfileService(body) {
    const user = users.find(user => user.uuid === body.uuid)
    if (!user) return { status: 404, message: { message: "User not found." } }
    return { status: 200, message: { ...user, password: undefined } }
}

async function editUserService(body) {
    const user = users.find(user => user.uuid === body.uuid)
    const { name, email, password } = body
    if (name) user.name = name
    if (email) user.email = email
    if (password) user.password = await hash(password, 10)
    if (body.token && body.isAdm) user.isAdm = body.isAdm;
    user.updatedOn = new Date();

    return { status: 200, message: { ...user, password: undefined } }
}

function deleteUserService(body) {
    const user = users.find(user => user.uuid === body.uuid)
    users.splice(user, 1)

    return { status: 204 }
}

//Controllers
async function registerController(req, res) {
    const { status, message } = await registerService(req.body)
    return res.status(status).json(message)
}

async function loginController(req, res) {
    const { status, message } = await loginService(req.body)
    return res.status(status).json(message)
}

function listUsersController(req, res) {
    const { status, message } = listUsersService(req.body);
    return res.status(status).json(message)
}

function displayProfileController(req, res) {
    const { status, message } = displayProfileService(req.body)
    return res.status(status).json(message)
}

async function editUserController(req, res) {
    const { status, message } = await editUserService(req.body)
    return res.status(status).json(message)
}

function deleteUserController(req, res) {
    deleteUserService(req.body)
    return res.status(204).json()
}

//Routes
app.post("/users", verifyRegisterMiddleware, registerController)
app.post("/login", verifyLoginMiddleware, loginController)
app.get("/users", verifyTokenMiddleware, listUsersController)
app.get("/users/profile", verifyTokenMiddleware, displayProfileController)
app.patch("/users/:uuid", verifyUuidRequested, editUserController)
app.delete("/users/:uuid", verifyUuidRequested, deleteUserController)

app.listen(4001, () => console.log(`Servidor está executando na porta 4001.`))
export default app