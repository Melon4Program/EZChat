const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*', // In production, restrict this to your frontend's domain
    methods: ['GET', 'POST'],
  },
});

// --- Configuration ---
const PORT = process.env.PORT || 3001;
const ADMIN_SECRET_KEY = 'kbs0721loVe!'; // Use a strong, unique key from environment variables in production
const JWT_SECRET_KEY = 'kbs0721loVe!'; // Use a strong, unique key from environment variables in production
const FILE_EXPIRATION_TIME = 2 * 60 * 60 * 1000; // 2 hours in milliseconds
const MAX_FILE_SIZE = 300 * 1024 * 1024; // 300MB in bytes

// --- Middleware ---
app.use(helmet());
app.use(cors());
app.use(express.json());

// --- REST API Endpoints ---

// Admin Login (for demonstration)
// In a real app, you'd have a proper user system.
app.post('/api/admin/login', (req, res) => {
    const { secretKey } = req.body;
    if (secretKey === ADMIN_SECRET_KEY) {
        const token = jwt.sign({ role: 'admin' }, JWT_SECRET_KEY, { expiresIn: '1h' });
        return res.json({ token });
    }
    res.status(401).json({ message: 'Invalid admin secret key.' });
});


// Room Creation (Admin only)
app.post('/api/rooms', adminAuth, async (req, res) => {
    const { roomName, password } = req.body;

    if (!roomName || !password) {
        return res.status(400).json({ message: 'Room name and password are required.' });
    }

    const sanitizedRoomName = sanitizeInput(roomName);
    if (rooms[sanitizedRoomName]) {
        return res.status(409).json({ message: 'Room already exists.' });
    }

    try {
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);
        rooms[sanitizedRoomName] = { passwordHash, messages: [] };
        console.log(`Room created: ${sanitizedRoomName}`);
        res.status(201).json({ message: `Room '${sanitizedRoomName}' created successfully.` });
    } catch (error) {
        console.error('Error hashing password:', error);
        res.status(500).json({ message: 'Server error while creating room.' });
    }
});

// File Upload Endpoint
app.post('/api/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded.' });
    }

    const { roomName, username } = req.body;
    if (!roomName || !username) {
        return res.status(400).json({ message: 'Room name and username are required.' });
    }

    const fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;

    // Broadcast the file message to the room
    const messageData = {
        username,
        message: `uploaded a file: ${req.file.originalname}`,
        fileUrl: fileUrl,
        fileName: req.file.originalname,
        isUpload: true, // Flag to identify this as a file upload message
        timestamp: new Date().toISOString(),
    };

    if (rooms[roomName]) {
        rooms[roomName].messages.push(messageData);
    }

    io.to(roomName).emit('newMessage', messageData);

    // Set a timer to delete the file after 2 hours
    setTimeout(() => {
        fs.unlink(req.file.path, (err) => {
            if (err) {
                console.error(`Error deleting file ${req.file.filename}:`, err);
            } else {
                console.log(`Successfully deleted expired file: ${req.file.filename}`);
            }
        });
    }, FILE_EXPIRATION_TIME);

    res.status(200).json({ message: 'File uploaded successfully.', fileUrl });
});

// Admin: Get all rooms, members, and chat history
app.get('/api/admin/rooms', adminAuth, (req, res) => {
    const roomDetails = Object.keys(rooms).map(roomName => {
        const members = Object.values(users)
            .filter(user => user.currentRoom === roomName)
            .map(user => user.username);
        
        return {
            roomName,
            members,
            messageCount: rooms[roomName].messages.length,
            messages: rooms[roomName].messages, // Include full history for admin
        };
    });
    res.json(roomDetails);
});

// --- Static File Serving ---

// Serve the static files from the React app
app.use(express.static(path.join(__dirname, 'public')));

// Serve uploaded files statically
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// SPA Fallback - This should be after all API routes and static file serving
// It sends the main HTML file for any request that doesn't match the above routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


// --- WebSocket (Socket.IO) Connection Handling ---
io.on('connection', (socket) => {
    console.log(`User connected: ${socket.id}`);

    socket.on('joinRoom', async ({ roomName, password, username }) => {
        const sanitizedRoomName = sanitizeInput(roomName);
        const sanitizedUsername = sanitizeInput(username);

        const room = rooms[sanitizedRoomName];
        if (!room) {
            return socket.emit('error', { message: 'Room does not exist.' });
        }

        try {
            const passwordMatch = await bcrypt.compare(password, room.passwordHash);
            if (!passwordMatch) {
                return socket.emit('error', { message: 'Invalid password.' });
            }

            socket.join(sanitizedRoomName);
            users[socket.id] = { username: sanitizedUsername, currentRoom: sanitizedRoomName };

            console.log(`${sanitizedUsername} (${socket.id}) joined room: ${sanitizedRoomName}`);

            // Notify user they have joined and send chat history
            socket.emit('joinedRoom', { 
                roomName: sanitizedRoomName,
                history: rooms[sanitizedRoomName].messages 
            });

            // Broadcast to others in the room that a new user has joined
            socket.to(sanitizedRoomName).emit('userJoined', {
                username: sanitizedUsername,
                message: `${sanitizedUsername} has joined the chat.`,
            });

        } catch (error) {
            console.error('Error during room join:', error);
            socket.emit('error', { message: 'Server error during authentication.' });
        }
    });

    socket.on('sendMessage', (message) => {
        const user = users[socket.id];
        if (user) {
            const { username, currentRoom } = user;
            const sanitizedMessage = sanitizeInput(message);
            
            const messageData = {
                username,
                message: sanitizedMessage,
                timestamp: new Date().toISOString(),
            };

            if (rooms[currentRoom]) {
                rooms[currentRoom].messages.push(messageData);
            }
            
            io.to(currentRoom).emit('newMessage', messageData);
        }
    });

    socket.on('leaveRoom', () => {
        const user = users[socket.id];
        if (user) {
            const { username, currentRoom } = user;
            delete users[socket.id];
            socket.leave(currentRoom);
            io.to(currentRoom).emit('userLeft', {
                username,
                message: `${username} has left the chat.`,
            });
            console.log(`${username} (${socket.id}) left room: ${currentRoom}`);
        }
    });


    socket.on('disconnect', () => {
        const user = users[socket.id];
        if (user) {
            const { username, currentRoom } = user;
            delete users[socket.id];
            
            // Notify others in the room that the user has left
            io.to(currentRoom).emit('userLeft', {
                username,
                message: `${username} has left the chat.`,
            });
            console.log(`${username} (${socket.id}) disconnected from ${currentRoom}`);
        } else {
            console.log(`User disconnected: ${socket.id}`);
        }
    });
});


// --- Server Initialization ---
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
