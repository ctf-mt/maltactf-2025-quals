const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();
const PORT = 3000;

let requestCount = 0;
const EARNINGS_PER_REQUEST = 13.37;

app.use(express.static('public'));

app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    next();
});

app.options('*', (req, res) => {
    res.sendStatus(200);
});

app.get('/ping', (req, res) => {
    requestCount++;
    console.log(`[Analytics] Ping received! Total requests: ${requestCount}`);
    res.json({ 
        success: true, 
        message: 'pong',
        totalRequests: requestCount,
        earnings: (requestCount * EARNINGS_PER_REQUEST).toFixed(2)
    });
});

app.get('/', (req, res) => {
    const totalEarnings = (requestCount * EARNINGS_PER_REQUEST).toFixed(2);
    
    try {
        const templatePath = path.join(__dirname, 'views', 'dashboard.html');
        let html = fs.readFileSync(templatePath, 'utf8');
        
        html = html.replace('{{requestCount}}', requestCount);
        html = html.replace('{{totalEarnings}}', totalEarnings);
        html = html.replace('{{earningsPerRequest}}', EARNINGS_PER_REQUEST);
        
        res.send(html);
    } catch (error) {
        console.error('Error reading template:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/integrate', (req, res) => {
    try {
        const templatePath = path.join(__dirname, 'views', 'integrate.html');
        let html = fs.readFileSync(templatePath, 'utf8');
        
        const domain = process.env.DOMAIN || 'web:1337';
        const analyticsDomain = process.env.ANALYTICS_DOMAIN || 'localhost:3000';
        
        const trustedOrigins = [
            domain.startsWith('http') ? domain : `http://${domain}`,
            analyticsDomain.startsWith('http') ? analyticsDomain : `http://${analyticsDomain}`
        ];
        
        html = html.replace('/*TRUSTED_ORIGINS*/', trustedOrigins.map(origin => `'${origin}'`).join(', '));
        
        res.send(html);
    } catch (error) {
        console.error('Error reading integrate template:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Analytics] Dashboard: http://analytics:${PORT}`);
}); 