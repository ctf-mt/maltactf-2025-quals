const toFancyText = (text) => {
    const fancyLowerStart = 0x1D51E; // 'a'
    const fancyUpperMap = {
        A: 0x1D504, B: 0x1D505, C: 0x212D, D: 0x1D507, E: 0x1D508,
        F: 0x1D509, G: 0x1D50A, H: 0x210C, I: 0x2111, J: 0x1D50D,
        K: 0x1D50E, L: 0x1D50F, M: 0x1D510, N: 0x1D511, O: 0x1D512,
        P: 0x1D513, Q: 0x1D514, R: 0x211C, S: 0x1D516, T: 0x1D517,
        U: 0x1D518, V: 0x1D519, W: 0x1D51A, X: 0x1D51B, Y: 0x1D51C, Z: 0x2128
    };

    return [...text].map(char => {
        const code = char.charCodeAt(0);

        // a-z
        if (code >= 97 && code <= 122) {
            return String.fromCodePoint(fancyLowerStart + (code - 97));
        }

        // A-Z
        if (char in fancyUpperMap) {
            return String.fromCodePoint(fancyUpperMap[char]);
        }

        // Leave others (numbers, punctuation) unchanged
        return char;
    }).join('');
}

contentBox.innerText = toFancyText(contentBox.innerText)
