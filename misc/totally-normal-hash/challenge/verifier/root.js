const wc  = require("./witness_calculator.js");
const { readFileSync } = require("fs");

if (process.argv.length != 3) {
    console.log("Usage: node root.js <input.json>");
} else {
    const input = JSON.parse(readFileSync(process.argv[2], "utf8"));
    const buffer = readFileSync(`${__dirname}/root.wasm`);
    wc(buffer).then(async witnessCalculator => {
            const w= await witnessCalculator.calculateWitness(input,0);
    });
}