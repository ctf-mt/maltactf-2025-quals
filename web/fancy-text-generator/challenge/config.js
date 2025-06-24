// TODO: add to actual config when it exists

const sleep = time => new Promise(resolve => setTimeout(resolve, time))

const challenges = new Map([
	  ['fancy-text-generator', {
		      name: 'fancy text generator',
		      timeout: 30000,
		      handler: async (url, ctx) => {
			            const page = await ctx.newPage();
			            await page.goto('http://PLACEHOLDER', { timeout: 3000 }); // TODO: add actual challenge url
			            await page.setCookie({ name: 'FLAG', value: 'maltactf{oops_my_dependency_is_buggy_05b19465ce19db4e28ddb00bb19f101e}'});
			            await page.goto(url, { timeout: 10000, waitUntil: 'domcontentloaded' });
			            await sleep(15000);
			          }
		    }],
])

module.exports = {
	  challenges
}
