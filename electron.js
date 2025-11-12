const { app, BrowserWindow } = require('electron');
const path = require('path');
const server = require('./server'); // Your express server

let mainWindow;
const PORT = 3001;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
  });

  // Load the local server URL
  mainWindow.loadURL(`http://localhost:${PORT}`);

  mainWindow.on('closed', function () {
    mainWindow = null;
  });
}

app.on('ready', () => {
  server.listen(PORT, () => {
    console.log(`Server started on port ${PORT} for Electron app`);
  });
  createWindow();
});

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') {
    server.close(() => {
      console.log('Server closed');
      app.quit();
    });
  }
});

app.on('activate', function () {
  if (mainWindow === null) {
    createWindow();
  }
});
