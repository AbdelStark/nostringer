const fs = require('fs');
const path = require('path');

// Walk through the dist/cjs directory
function processDirectory(directory) {
  const entries = fs.readdirSync(directory, { withFileTypes: true });
  
  for (const entry of entries) {
    const entryPath = path.join(directory, entry.name);
    
    if (entry.isDirectory()) {
      processDirectory(entryPath);
    } else if (entry.isFile() && entry.name.endsWith('.js')) {
      // Rename .js files to .cjs
      const newPath = entryPath.replace(/\.js$/, '.cjs');
      fs.renameSync(entryPath, newPath);
      
      // Update imports in .cjs files
      if (newPath.endsWith('.cjs')) {
        let content = fs.readFileSync(newPath, 'utf8');
        // Replace relative imports with .cjs extension
        content = content.replace(/require\(['"]([^'"]+)\.js['"]\)/g, "require('$1.cjs')");
        fs.writeFileSync(newPath, content, 'utf8');
      }
    }
  }
}

// Start processing from dist/cjs
const cjsDir = path.join(__dirname, '..', 'dist', 'cjs');
if (fs.existsSync(cjsDir)) {
  processDirectory(cjsDir);
  console.log('Successfully renamed CommonJS files to use .cjs extension');
} else {
  console.error('CJS directory not found:', cjsDir);
}

// Update package.json main field to point to .cjs file
const packageJsonPath = path.join(__dirname, '..', 'package.json');
const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));

// Make sure paths include src directory
const mainPath = './dist/cjs/src/index.cjs';
const requirePath = './dist/cjs/src/index.cjs';
const importPath = './dist/esm/src/index.js';
const typesPath = './dist/esm/src/index.d.ts';

packageJson.main = mainPath;

if (packageJson.exports && packageJson.exports['.']) {
  packageJson.exports['.'].require = requirePath;
  packageJson.exports['.'].import = importPath;
  packageJson.exports['.'].types = typesPath;
}

fs.writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2), 'utf8');
console.log('Updated package.json to reference .cjs files'); 