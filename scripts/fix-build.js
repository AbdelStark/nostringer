const fs = require('fs');
const path = require('path');

// Add type: module to ESM directory
function addTypeModuleToEsm() {
  const esmDir = path.join(__dirname, '..', 'dist', 'esm');
  const packageJsonPath = path.join(esmDir, 'package.json');
  
  const packageJsonContent = {
    "type": "module"
  };
  
  fs.writeFileSync(packageJsonPath, JSON.stringify(packageJsonContent, null, 2));
  console.log('Added type:module to ESM directory');
}

// Fix CJS files by updating require paths and renaming to .cjs
function processCJSDirectory(directory) {
  const entries = fs.readdirSync(directory, { withFileTypes: true });
  
  for (const entry of entries) {
    const entryPath = path.join(directory, entry.name);
    
    if (entry.isDirectory()) {
      processCJSDirectory(entryPath);
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

// Remove unnecessary files (test files from dist)
function removeTestFiles() {
  const removeDirectories = [
    path.join(__dirname, '..', 'dist', 'cjs', 'test'),
    path.join(__dirname, '..', 'dist', 'esm', 'test'),
    path.join(__dirname, '..', 'dist', 'test')  // Old dist folder
  ];
  
  for (const dir of removeDirectories) {
    if (fs.existsSync(dir)) {
      console.log(`Removing directory: ${dir}`);
      removeDirectory(dir);
    }
  }
}

function removeDirectory(directory) {
  if (fs.existsSync(directory)) {
    const files = fs.readdirSync(directory);
    
    for (const file of files) {
      const filePath = path.join(directory, file);
      const stats = fs.statSync(filePath);
      
      if (stats.isDirectory()) {
        removeDirectory(filePath);
      } else {
        fs.unlinkSync(filePath);
      }
    }
    
    fs.rmdirSync(directory);
  }
}

// Update package.json
function updatePackageJson() {
  const packageJsonPath = path.join(__dirname, '..', 'package.json');
  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  
  // Make sure paths include src directory and use correct extensions
  const mainPath = './dist/cjs/src/index.cjs';
  const requirePath = './dist/cjs/src/index.cjs';
  const importPath = './dist/esm/src/index.js';
  const typesPath = './dist/esm/src/index.d.ts';
  
  packageJson.main = mainPath;
  packageJson.module = importPath;
  packageJson.types = typesPath;
  
  if (packageJson.exports && packageJson.exports['.']) {
    packageJson.exports['.'].require = requirePath;
    packageJson.exports['.'].import = importPath;
    packageJson.exports['.'].types = typesPath;
  }
  
  fs.writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2));
  console.log('Updated package.json with correct paths');
}

// Execute all fixes
function main() {
  // Fix CJS files
  const cjsDir = path.join(__dirname, '..', 'dist', 'cjs');
  if (fs.existsSync(cjsDir)) {
    processCJSDirectory(cjsDir);
    console.log('Successfully renamed CommonJS files to use .cjs extension');
  } else {
    console.error('CJS directory not found:', cjsDir);
  }
  
  // Add type: module to ESM directory
  addTypeModuleToEsm();
  
  // Remove test files
  removeTestFiles();
  
  // Update package.json
  updatePackageJson();
  
  console.log('Build fixes complete!');
}

main(); 