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

app.get('/', async (req, res) => {
    res.sendFile(`${__dirname}/public/scanner.html`);
});

app.get('/scanner', async (req, res) => {
    console.log('get request');

    const globalURL = req.query.url;
    const hasXSS = await check_xss(globalURL);
    res.send(hasXSS);
});

const MALICIOUS_SCRIPT = ['<script>alert("xss")</script>', '<image src=1 href=1 onerror="javascript:alert(1)"></image>', '\')%3Balert(1)%3Bvar b=(\'', '<iframe onReadyStateChange iframe onReadyStateChange="javascript:javascript:alert(1)"></iframe onReadyStateChange>', '<html onMouseOut html onMouseOut="javascript:javascript:alert(1)"></html onMouseOut>', '<img src="http://inexist.ent" onerror="javascript:alert(1)"/>'];

async function check_xss(url) {
    const browser = await puppeteer.launch({
        headless: 'new', defaultViewport: null, args: ['--start-maximized']
    });
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: 'networkidle2' });
    const formsArray = await page.$$('form');
    const page2 = await browser.newPage();
    let isVulnerable = false;
    page2.on('dialog', async (dialog) => {
        isVulnerable = true;
        await dialog.accept();
    });

    for (const script in MALICIOUS_SCRIPT) {
        let newUrl = check_url(url, MALICIOUS_SCRIPT[script]);

        if (newUrl !== '') {
            await page2.goto(newUrl);
        }

        if (isVulnerable) {
            await browser.close();

            return true;
        }

        for (const formArray of formsArray) {
            try {
                await page2.goto(url, { waitUntil: 'networkidle2', timeout: 60000 });
                const inputsArray = await formArray.$$eval(
                    'input[type="text"],input[type="search"],input:not([type]),textarea',
                    (inputs) => inputs.map((input) => input.name)
                );

                for (const selector of inputsArray) {
                    await page2.type(`[name="${selector}"]`, MALICIOUS_SCRIPT[script], { delay: 20 });
                }

                const buttonsArray = await formArray.$$eval(
                    'input[type="submit"],button[type="submit"]',
                    (subs) => subs.map(
                        (sub) => sub.id
                            ? `#${sub.id}`
                            : (sub.className ? `.${sub.className.split(' ').join('.')}` : `[name="${sub.name}"`)
                    )
                );

                const submitButton = buttonsArray[0];
                await page2.click(submitButton);

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
