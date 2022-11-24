import express from "express";
import users from "./database";
import { hash, compare } from "bcryptjs";
import { v4 as uuidv4 } from "uuid";
import 'dotenv/config';

const app = express()
app.use(express.json())


//Middlewares

//Services


//Controllers


//Routes

app.listen(4001, () => console.log(`Servidor está executando na porta 4001`))
export default app