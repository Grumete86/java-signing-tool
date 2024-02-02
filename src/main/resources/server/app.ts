import express from 'express';
import bodyParser from 'body-parser'
import { sign } from './src/sign'

// default running port
const PORT = process.env.PORT || 5432;

// creating the app instance
const app = express();

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }))

// parse application/json
app.use(bodyParser.json())

// receiving the request and processing
app.post("/", (request, response) => {
    // obtaining needed values: credential to sign, private key, and verification method
    const json_credential = JSON.parse(request.body.credential)
    const stringKey = request.body.key
    const verificationMethod = request.body.verification_method

    // calling the method to create the signed credential
    // the obtained object is a Promise
    const signedCredential = sign(
        stringKey,
        json_credential,
        verificationMethod
    )
    // we process the Promise, to send the credential in json string
    signedCredential
    .then(cred => JSON.stringify(cred))
    .then(json => response.send(json))
})

// run the app an listen to the defined PORT
app.listen(PORT, () => {
    console.log("Server Listening on PORT:", PORT);
});
