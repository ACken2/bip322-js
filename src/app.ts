import express, { Request, Response } from 'express';
import Signer from './Signer';
import Verifier from './Verifier'; 
import BIP322 from './BIP322'; 

const app = express();
const port = 3000;

app.use(express.json());

// API endpoint for signing
app.post('/sign', (req: Request, res: Response) => {
    try {
        const { privateKey, address, message } = req.body;
        const signature = Signer.sign(privateKey, address, message);
        res.json({ signature });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// API endpoint for verifySignature
app.post('/verifySignature', (req: Request, res: Response) => {
    try {
        const { signerAddress, message, signatureBase64 } = req.body;
        const isValid = Verifier.verifySignature(signerAddress, message, signatureBase64);
        res.json({ isValid });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// API endpoint for hashMessage
app.post('/hashMessage', (req: Request, res: Response) => {
    try {
        const { message } = req.body;
        const hashMessage = BIP322.hashMessage(message);
        res.json({ hashMessage });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`);
});
