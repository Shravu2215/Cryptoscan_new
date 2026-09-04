const fs = require('fs');
const files = ['scan.html', 'cbom.html', 'profile.html', 'settings.html', 'verification.html', 'repositories.html'];

files.forEach(file => {
  let content = fs.readFileSync('frontend/' + file, 'utf-8');
  
  content = content.replace(/<aside class="sidebar">[\s\S]*?<\/aside>/, '<aside class="app-sidebar" id="app-sidebar"></aside>');
  content = content.replace(/<aside class="sb">[\s\S]*?<\/aside>/, '<aside class="app-sidebar" id="app-sidebar"></aside>');
  
  content = content.replace(/<header class="topbar">[\s\S]*?<\/header>/, '<header class="app-topbar" id="app-topbar"></header>');
  
  if (!content.includes('shell.js')) {
    content = content.replace('</body>', '<script src="assets/js/shell.js"></script>\n</body>');
  }
  
  if (!content.includes('global.css')) {
    content = content.replace('</head>', '  <link rel="stylesheet" href="assets/css/global.css">\n</head>');
  }

  fs.writeFileSync('frontend/' + file, content, 'utf-8');
  console.log('Processed ' + file);
});
