scripts = {
    "pace": "https://cdn.jsdelivr.net/npm/pace-js@latest/pace.min.js",
    "main": "/main.js",
}

function appendScript (src) {
    let script = document.createElement('script');
    script.src = src;
    document.head.appendChild(script);
};

for (let script in scripts) {
    appendScript(scripts[script]);
}
