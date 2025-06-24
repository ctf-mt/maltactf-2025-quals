const express = require('express');
const path = require('path');
const http = require('http');
const visitUrl = require('./bot');

const app = express();
const PORT = process.env.PORT || 1337;

app.use(express.json());
app.use(express.static('views'));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

app.get('/ad.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'ad.html'));
});

app.post('/bot', async (req, res) => {
    const { url } = req.body;

    if (!url) {
        return res.status(400).json({ error: 'URL is required' });
    }

    try {
        const parsedUrl = new URL(url);
        if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
            return res.status(400).json({ error: 'Invalid URL protocol' });
        }

        await visitUrl(url);
        res.json({ success: true, message: 'URL has been visited' });

    } catch (error) {
        console.error('Error processing URL visit:', error);
        res.status(400).json({ error: 'Invalid URL or visit failed' });
    }
});

http.createServer(app).listen(PORT, '0.0.0.0', () => {
    console.log(`[*] HTTP Server running on port ${PORT}`);
}); 