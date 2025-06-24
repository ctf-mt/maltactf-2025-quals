const express = require('express')
const app = express();
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

app.set('view engine', 'ejs');
app.use(express.static('static'))

app.use((req, res, next) => {
    res.set('Content-Security-Policy', "script-src 'sha256-1ltlTOtatSNq5nY+DSYtbldahmQSfsXkeBYmBH5i9dQ=' 'strict-dynamic'; object-src 'none';");
    next();
  });

app.get('/', (req, res) => {
    const window = new JSDOM('').window;
    const DOMPurify = createDOMPurify(window);
    return res.render('index', {text: DOMPurify.sanitize(req.query.text)})
})

app.listen(process.env.PORT || 1337, () => {
    console.log(`listening on ${process.env.PORT || 1337}`)
})
