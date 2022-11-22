const resource = [
    /* --- CSS --- */
    '/assets/css/style.css',

    /* --- PWA --- */
    '/app.js',
    '/sw.js',

    /* --- HTML --- */
    '/index.html',
    '/404.html',

    
        '/categories/',
    
        '/tags/',
    
        '/archives/',
    
        '/about/',
    

    /* --- Favicons & compressed JS --- */
    
    
        '/assets/img/favicons/android-chrome-192x192.png',
        '/assets/img/favicons/android-chrome-512x512.png',
        '/assets/img/favicons/apple-touch-icon.png',
        '/assets/img/favicons/favicon-16x16.png',
        '/assets/img/favicons/favicon-32x32.png',
        '/assets/img/favicons/favicon.ico',
        '/assets/img/favicons/mstile-150x150.png',
        '/assets/js/dist/categories.min.js',
        '/assets/js/dist/commons.min.js',
        '/assets/js/dist/home.min.js',
        '/assets/js/dist/misc.min.js',
        '/assets/js/dist/page.min.js',
        '/assets/js/dist/post.min.js',
        '/assets/js/dist/pvreport.min.js',
        '/assets/img/favicons/.jekyll-cache/.gitignore',
        '/assets/img/favicons/.jekyll-cache/Jekyll/Cache/Jekyll--Cache/b7/9606fb3afea5bd1609ed40b622142f1c98125abcfe89a76a661b0e8e343910',
        '/assets/img/favicons/_site/android-chrome-192x192.png',
        '/assets/img/favicons/_site/android-chrome-512x512.png',
        '/assets/img/favicons/_site/apple-touch-icon.png',
        '/assets/img/favicons/_site/browserconfig.xml',
        '/assets/img/favicons/_site/favicon-16x16.png',
        '/assets/img/favicons/_site/favicon-32x32.png',
        '/assets/img/favicons/_site/favicon.ico',
        '/assets/img/favicons/_site/mstile-150x150.png',
        '/assets/img/favicons/_site/site.webmanifest'
];

/* The request url with below domain will be cached */
const allowedDomains = [
    

    'localhost:4000',

    

    'fonts.gstatic.com',
    'fonts.googleapis.com',
    'cdn.jsdelivr.net',
    'polyfill.io'
];

/* Requests that include the following path will be banned */
const denyUrls = [
    
];

