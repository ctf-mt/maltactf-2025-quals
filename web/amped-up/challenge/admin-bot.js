// This is a reference for what the admin bot will do, and is not intended as a complete runner.
// You can assume that the only actions performed by the admin bot are:
// - Set a flag on the challenge domain using `localStorage`
// - Load the challenge with `?skin=<skin>`
// - Idle for a few seconds
const sleep = time => new Promise(resolve => setTimeout(resolve, time))

const challenges = new Map([
    ['amped-up', {
        name: 'Amped Up',
        timeout: 10000,
        handler: async (url, ctx) => {
            const page = await ctx.newPage();
            await page.goto('https://amped-up.challs.mt/', { timeout: 3000 });
            await page.evaluate(() => {
                localStorage.setItem('flag', 'flag{fake_flag}');
            });
            await page.goto(`https://amped-up.challs.mt/?skin=${encodeURIComponent(url)}`, { timeout: 3000 });
            await sleep(5000);
        }
    }]
]);

module.exports = {
    challenges
};