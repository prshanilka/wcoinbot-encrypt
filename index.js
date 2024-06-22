require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const {
  encryptData
} = require('./utils');


const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json());
app.post('/encrypt', async (req, res) => {

  try {
    const { dataToEncrypt } = req.body;
    if (!dataToEncrypt) {
      return res.status(400).json({ error: 'No data provided for encryption' });
    }

    const encryptedData = await encryptData(dataToEncrypt);
    res.json({ encryptedData });
  } catch (error) {
    res.status(500).json({ error: 'Encryption failed', details: error.message });
  }
});

app.get('/', (req, res) => {
  res.status(200).send('OK');
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});