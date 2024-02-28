import queryString from 'query-string';
import http from 'http';
import express from 'express';
import bodyParser from 'body-parser';
import puppeteer from 'puppeteer';
import path from 'path';
import { fileURLToPath } from 'url';

const app = express();
const server = http.createServer(app);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// strona główna z formularzem
app.get('/', async (req, res) => {
    res.sendFile(`${__dirname}/public/scanner.html`);
});

// strona do której kieruje formularz
app.get('/scanner', async (req, res) => {
    console.log('get request');

    // pobranie url strony do testów z adresu
    const globalURL = req.query.url;
    // odpalenie testu na podanej stronie
    const hasXSS = await check_xss(globalURL);
    res.send(hasXSS);
});

const MALICIOUS_SCRIPT = ['<script>alert("xss")</script>', '<image src=1 href=1 onerror="javascript:alert(1)"></image>', '\')%3Balert(1)%3Bvar b=(\'', '<iframe onReadyStateChange iframe onReadyStateChange="javascript:javascript:alert(1)"></iframe onReadyStateChange>', '<html onMouseOut html onMouseOut="javascript:javascript:alert(1)"></html onMouseOut>', '<img src="http://inexist.ent" onerror="javascript:alert(1)"/>'];

async function check_xss(url) {
    // tworzy instancje przeglądarki
    const browser = await puppeteer.launch({
        headless: 'new', defaultViewport: null, args: ['--start-maximized']
    });
    // przechodzi do podanej strony
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: 'networkidle2' });

    // wyszukuje wszystkie formularze na stronie
    const formsArray = await page.$$('form');

    // tworzy nową "kartę" na potrzeby otwierania/przesylania formularzy
    const page2 = await browser.newPage();
    let isVulnerable = false;
    // zapina się na tej karcie na zdarzenie wyskakującego dialogu - takie coś następuje, gdy uda się wstrzyknąć złośliwy kod
    page2.on('dialog', async (dialog) => {
        isVulnerable = true;
        await dialog.accept();
    });

    // pętla po skryptach do wstrzyknięcia
    for (const script in MALICIOUS_SCRIPT) {
        // tworzy nowy url ze wstrzykniętym w niego skryptem
        let newUrl = check_url(url, MALICIOUS_SCRIPT[script]);

        if (newUrl !== '') {
            await page2.goto(newUrl);
        }

        // jeśli wykryto zagrożenie, zamyka kartę - tę flągę zmienia linia 52
        if (isVulnerable) {
            await browser.close();

            return true;
        }

        // pętla po znalezionych formularzach
        for (const formArray of formsArray) {
            try {
                await page2.goto(url, { waitUntil: 'networkidle2', timeout: 60000 });
                // szuka wszystkich pól do wpisywania tekstu w formularzu
                const inputsArray = await formArray.$$eval(
                    'input[type="text"],input[type="search"],input:not([type]),textarea',
                    (inputs) => inputs.map((input) => input.name)
                );

                // wypełnia wszystkie pola z tekstem skryptem
                for (const selector of inputsArray) {
                    await page2.type(`[name="${selector}"]`, MALICIOUS_SCRIPT[script], { delay: 20 });
                }

                // szuka przycisku do wysłania formularza
                const buttonsArray = await formArray.$$eval(
                    'input[type="submit"],button[type="submit"]',
                    (subs) => subs.map(
                        (sub) => sub.id
                            ? `#${sub.id}`
                            : (sub.className
                                ? `.${sub.className
                                    .split(' ')
                                    .map(className => className.replace(/([\\[\]#:])/g, '\\$1'))
                                    .join('.')}`
                                : `[name="${sub.name}"`)
                    )
                );

                const submitButton = buttonsArray[0];
                // KLIIIIIK :D
                await page2.click(submitButton);

                // formularz mógłbyć typu "GET", w takim wypadku warto spróbować ponownie podmienić wszystkie parametry w adresie i ponownie go sprawdzić
                // (skrypty mogły byc wycięte przy klikaniu)
                newUrl = check_url(page2.url(), MALICIOUS_SCRIPT[script]);

                if (newUrl !== '') {
                    await page2.goto(newUrl);
                }
            } catch (error) {
                await browser.close();

                return error.message;
            }
        }

        await new Promise((resolve) => setTimeout(resolve, 2000));

        if (isVulnerable) {
            await browser.close();

            return true;
        }
    }

    await browser.close();
    await new Promise((resolve) => setTimeout(resolve, 2000));

    return isVulnerable;
}

const check_url = (url, script) => {
    let temp = {};
    let newUrl = '';
    temp = url.split('?');
    const tmp = queryString.parse(temp[1]);
    const key = Object.keys(tmp);

    if (temp[1]) {
        newUrl = `${temp[0] }?`;

        for (const k in tmp) {
            if (key[0] === k) {
                newUrl = `${newUrl + k }=${ script}`;
            } else {
                newUrl = `${newUrl }&${ k }=${ script}`;
            }
        }
    }

    return newUrl;
};

server.listen(process.env.PORT || 4000, () => console.log('Server has started.'));

// https://xss-game.appspot.com/level1/frame
// https://xss-game.appspot.com/level2/frame
// https://xss-game.appspot.com/level4/frame
// https://www.wikipedia.org
//  https://gibiru.com/
