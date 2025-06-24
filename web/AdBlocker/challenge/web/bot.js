const puppeteer = require('puppeteer');

async function visitUrl(url) {
    const browser = await puppeteer.launch({
        headless: 'new',
        executablePath: '/usr/bin/chromium-browser',
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-gpu',
            '--disable-wasm',
            '--disable-jit',
            '--window-size=1920,1080',
            '--ignore-certificate-errors',
            '--ignore-ssl-errors',
            '--allow-running-insecure-content'
        ]
    });

    try {
        const page = await browser.newPage();

        await page.goto(process.env.ANALYTICS_URL, {
            waitUntil: 'domcontentloaded',
            timeout: 3000
        });

        await page.setCookie({
            name: 'flag',
            value: process.env.FLAG || 'maltactf{fake_flag}',
            secure: false,
            sameSite: 'Lax',
            httpOnly: false
        });


        console.log(`[Bot] Visiting user URL: ${url}`);
        await page.goto(url, {
            waitUntil: 'domcontentloaded',
            timeout: 10000
        });

        console.log('[Bot] Waiting on target page...');
        await new Promise(resolve => setTimeout(resolve, 10000));

    } catch (err) {
        console.error('Bot error:', err);
    } finally {
        if (browser) {
            try {
                await browser.close();
                console.log('[Bot] Browser closed successfully');
            } catch (closeErr) {
                console.error('Error closing browser:', closeErr);
            }
        }
    }
}

module.exports = visitUrl; 