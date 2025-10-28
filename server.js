const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const https = require('https');
const crypto = require('crypto');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Database files
const USERS_DB = 'database.json';
const ADMINS_DB = 'admin.json';
const HISTORY_DB = 'history.json';

// TikTok Bot Variables
let botReqs = 0, botSuccess = 0, botFails = 0;
let botRps = 0, botRpm = 0;
let botTargetViews = 0;
let botRunning = false;
let currentVideoId = '';
let originalViews = 0;
let videoTitle = '';

// Initialize databases
function initDB() {
    if (!fs.existsSync(USERS_DB)) fs.writeFileSync(USERS_DB, '[]');
    if (!fs.existsSync(ADMINS_DB)) fs.writeFileSync(ADMINS_DB, '{"referral_codes": [], "settings": {}}');
    if (!fs.existsSync(HISTORY_DB)) fs.writeFileSync(HISTORY_DB, '[]');
}

function readDB(file) { 
    try {
        return JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (e) {
        return [];
    }
}
function writeDB(file, data) { fs.writeFileSync(file, JSON.stringify(data, null, 2)); }

// ================= WEBSITE ROUTES =================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// ================= AUTHENTICATION ROUTES =================
app.post('/api/register', async (req, res) => {
    const { email, password, referral_code } = req.body;
    
    if (!email || !password || !referral_code) {
        return res.status(400).json({ success: false, message: 'All fields required' });
    }
    
    const adminData = readDB(ADMINS_DB);
    if (!adminData.referral_codes.includes(referral_code)) {
        return res.status(400).json({ success: false, message: 'Invalid referral code' });
    }
    
    const users = readDB(USERS_DB);
    if (users.find(u => u.email === email)) {
        return res.status(400).json({ success: false, message: 'Email already registered' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
        id: Date.now().toString(),
        email,
        password: hashedPassword,
        referral_code,
        created_at: new Date().toISOString(),
        status: 'active'
    };
    
    users.push(newUser);
    writeDB(USERS_DB, users);
    
    adminData.referral_codes = adminData.referral_codes.filter(code => code !== referral_code);
    writeDB(ADMINS_DB, adminData);
    
    res.json({ success: true, message: 'Registration successful' });
});

app.post('/api/login', async (req, res) => {
    const { email, password, remember } = req.body;
    
    const users = readDB(USERS_DB);
    const user = users.find(u => u.email === email);
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).json({ success: false, message: 'Invalid email or password' });
    }
    
    const token = jwt.sign({ userId: user.id, email: user.email }, 'your-secret-key-123', {
        expiresIn: remember ? '30d' : '1d'
    });
    
    res.json({ 
        success: true, 
        message: 'Login successful',
        token,
        user: { email: user.email }
    });
});

// ================= TIKTOK VIDEO INFO =================
async function getTikTokVideoInfo(videoUrl) {
    try {
        // Convert short URL to full URL
        let finalUrl = videoUrl;
        if (videoUrl.includes('vt.tiktok.com') || videoUrl.includes('vm.tiktok.com')) {
            const response = await axios.get(videoUrl, {
                maxRedirects: 0,
                validateStatus: function (status) {
                    return status >= 200 && status < 400;
                }
            });
            finalUrl = response.headers.location || videoUrl;
        }

        // Extract video ID
        let videoId = '';
        const idMatch1 = finalUrl.match(/\d{18,19}/g);
        const idMatch2 = finalUrl.match(/video\/(\d+)/);
        
        if (idMatch1) {
            videoId = idMatch1[0];
        } else if (idMatch2) {
            videoId = idMatch2[1];
        }

        if (!videoId) {
            throw new Error('Could not extract video ID');
        }

        // Get video info from TikTok API
        const apiUrl = `https://www.tiktok.com/node/share/video/${videoId}`;
        const response = await axios.get(apiUrl, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        });

        if (response.data && response.data.itemInfo && response.data.itemInfo.itemStruct) {
            const videoData = response.data.itemInfo.itemStruct;
            return {
                success: true,
                videoId: videoId,
                title: videoData.desc || 'No Title',
                views: videoData.stats.playCount || 0,
                likes: videoData.stats.diggCount || 0,
                shares: videoData.stats.shareCount || 0,
                comments: videoData.stats.commentCount || 0,
                author: videoData.author ? videoData.author.uniqueId : 'Unknown'
            };
        } else {
            // Fallback: Return basic info
            return {
                success: true,
                videoId: videoId,
                title: 'TikTok Video',
                views: 0,
                likes: 0,
                shares: 0,
                comments: 0,
                author: 'Unknown'
            };
        }
    } catch (error) {
        console.log('Error getting TikTok info:', error.message);
        // Fallback: Extract video ID and return basic info
        let videoId = '';
        const idMatch = videoUrl.match(/\d{18,19}/g);
        if (idMatch) videoId = idMatch[0];
        
        return {
            success: true,
            videoId: videoId,
            title: 'TikTok Video',
            views: 0,
            likes: 0,
            shares: 0,
            comments: 0,
            author: 'Unknown'
        };
    }
}

// ================= TIKTOK BOT ROUTES =================
app.post('/api/tiktok/info', authenticateToken, async (req, res) => {
    const { video_url } = req.body;
    
    try {
        const videoInfo = await getTikTokVideoInfo(video_url);
        res.json(videoInfo);
    } catch (error) {
        res.json({ 
            success: false, 
            message: 'Error fetching video info: ' + error.message 
        });
    }
});

app.post('/api/tiktok/start', authenticateToken, async (req, res) => {
    const { video_url, target_views } = req.body;
    const user = req.user;
    
    if (botRunning) {
        return res.json({ success: false, message: 'Bot is already running' });
    }
    
    try {
        // Get video info and original views
        const videoInfo = await getTikTokVideoInfo(video_url);
        if (!videoInfo.success) {
            return res.json({ success: false, message: 'Invalid TikTok URL' });
        }
        
        const aweme_id = videoInfo.videoId;
        const targetViews = parseInt(target_views);
        originalViews = videoInfo.views;
        videoTitle = videoInfo.title;
        
        // Save to history
        const history = readDB(HISTORY_DB);
        const historyItem = {
            id: Date.now().toString(),
            userId: user.userId,
            videoUrl: video_url,
            videoId: aweme_id,
            videoTitle: videoInfo.title,
            originalViews: originalViews,
            targetViews: targetViews,
            timestamp: new Date().toISOString()
        };
        history.push(historyItem);
        writeDB(HISTORY_DB, history);
        
        // Start bot in background
        startTikTokBot(aweme_id, targetViews, originalViews);
        
        res.json({ 
            success: true, 
            message: 'TikTok bot started successfully!',
            video_id: aweme_id,
            video_title: videoInfo.title,
            original_views: originalViews,
            target_views: targetViews,
            total_target: originalViews + targetViews
        });
    } catch (error) {
        res.json({ success: false, message: 'Error: ' + error.message });
    }
});

app.post('/api/tiktok/stop', authenticateToken, (req, res) => {
    botRunning = false;
    res.json({ success: true, message: 'TikTok bot stopped' });
});

app.get('/api/tiktok/stats', authenticateToken, (req, res) => {
    res.json({
        success: true,
        running: botRunning,
        stats: {
            success: botSuccess,
            fails: botFails,
            reqs: botReqs,
            rps: botRps,
            rpm: botRpm,
            target_views: botTargetViews,
            original_views: originalViews,
            progress: botSuccess,
            total_target: originalViews + botTargetViews,
            video_id: currentVideoId,
            video_title: videoTitle
        }
    });
});

// ================= HISTORY ROUTES =================
app.get('/api/history', authenticateToken, (req, res) => {
    const user = req.user;
    const history = readDB(HISTORY_DB);
    const userHistory = history.filter(item => item.userId === user.userId)
                              .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
                              .slice(0, 20); // Last 20 items
    res.json({ success: true, history: userHistory });
});

app.delete('/api/history/:id', authenticateToken, (req, res) => {
    const user = req.user;
    const historyId = req.params.id;
    
    const history = readDB(HISTORY_DB);
    const updatedHistory = history.filter(item => !(item.id === historyId && item.userId === user.userId));
    writeDB(HISTORY_DB, updatedHistory);
    
    res.json({ success: true, message: 'History item deleted' });
});

// ================= ADMIN ROUTES =================
app.post('/admin/generate-referral', (req, res) => {
    const { admin_key } = req.body;
    
    if (admin_key !== 'YOUR_ADMIN_SECRET_123') {
        return res.status(403).json({ success: false, message: 'Unauthorized' });
    }
    
    const referralCode = 'REF_' + Math.random().toString(36).substr(2, 8).toUpperCase();
    const adminData = readDB(ADMINS_DB);
    adminData.referral_codes.push(referralCode);
    writeDB(ADMINS_DB, adminData);
    
    res.json({ success: true, referral_code: referralCode });
});

app.post('/admin/get-codes', (req, res) => {
    const { admin_key } = req.body;
    
    if (admin_key !== 'YOUR_ADMIN_SECRET_123') {
        return res.status(403).json({ success: false, message: 'Unauthorized' });
    }
    
    const adminData = readDB(ADMINS_DB);
    res.json({ success: true, codes: adminData.referral_codes || [] });
});

app.post('/admin/generate-custom-referral', (req, res) => {
    const { admin_key, custom_code } = req.body;
    
    if (admin_key !== 'YOUR_ADMIN_SECRET_123') {
        return res.status(403).json({ success: false, message: 'Unauthorized' });
    }
    
    if (!custom_code || custom_code.length < 3) {
        return res.json({ success: false, message: 'Custom code must be at least 3 characters' });
    }
    
    const adminData = readDB(ADMINS_DB);
    
    if (!adminData.referral_codes) {
        adminData.referral_codes = [];
    }
    
    if (adminData.referral_codes.includes(custom_code)) {
        return res.json({ success: false, message: 'Custom code already exists' });
    }
    
    adminData.referral_codes.push(custom_code);
    writeDB(ADMINS_DB, adminData);
    
    res.json({ success: true, referral_code: custom_code });
});

app.post('/admin/delete-referral', (req, res) => {
    const { admin_key, referral_code } = req.body;
    
    if (admin_key !== 'YOUR_ADMIN_SECRET_123') {
        return res.status(403).json({ success: false, message: 'Unauthorized' });
    }
    
    const adminData = readDB(ADMINS_DB);
    
    if (!adminData.referral_codes) {
        adminData.referral_codes = [];
    }
    
    adminData.referral_codes = adminData.referral_codes.filter(code => code !== referral_code);
    writeDB(ADMINS_DB, adminData);
    
    res.json({ success: true, message: 'Referral code deleted' });
});

app.get('/admin/users', (req, res) => {
    const adminKey = req.headers['authorization'];
    
    if (adminKey !== 'YOUR_ADMIN_SECRET_123') {
        return res.status(403).json({ success: false, message: 'Unauthorized' });
    }
    
    const users = readDB(USERS_DB);
    res.json(users);
});

// ================= TIKTOK BOT FUNCTIONS =================
function gorgon(params, data, cookies, unix) {
    function md5(input) {
        return crypto.createHash('md5').update(input).digest('hex');
    }
    let baseStr = md5(params) + (data ? md5(data) : '0'.repeat(32)) + (cookies ? md5(cookies) : '0'.repeat(32));
    return {
        'X-Gorgon': '0404b0d300000000000000000000000000000000',
        'X-Khronos': unix.toString()
    };
}

function sendTikTokRequest(did, iid, cdid, openudid, aweme_id) {
    return new Promise((resolve) => {
        if (!botRunning) {
            resolve();
            return;
        }

        const params = `device_id=${did}&iid=${iid}&device_type=SM-G973N&app_name=musically_go&host_abi=armeabi-v7a&channel=googleplay&device_platform=android&version_code=160904&device_brand=samsung&os_version=9&aid=1340`;
        const payload = `item_id=${aweme_id}&play_delta=1`;
        const sig = gorgon(params, null, null, Math.floor(Date.now() / 1000));
        
        const options = {
            hostname: 'api16-va.tiktokv.com',
            port: 443,
            path: `/aweme/v1/aweme/stats/?${params}`,
            method: 'POST',
            headers: {
                'cookie': 'sessionid=90c38a59d8076ea0fbc01c8643efbe47',
                'x-gorgon': sig['X-Gorgon'],
                'x-khronos': sig['X-Khronos'],
                'user-agent': 'okhttp/3.10.0.1',
                'content-type': 'application/x-www-form-urlencoded',
                'content-length': Buffer.byteLength(payload)
            },
            timeout: 5000
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            res.on('end', () => {
                botReqs++;
                try {
                    const jsonData = JSON.parse(data);
                    if (jsonData && jsonData.log_pb && jsonData.log_pb.impr_id) {
                        botSuccess++;
                        console.log(`✅ TikTok Views: ${botSuccess}/${botTargetViews} | Total: ${originalViews + botSuccess}`);
                        
                        if (botSuccess >= botTargetViews) {
                            console.log('🎉 TikTok Target Completed!');
                            botRunning = false;
                        }
                    } else {
                        botFails++;
                    }
                } catch (e) {
                    botFails++;
                }
                resolve();
            });
        });

        req.on('error', (e) => {
            botFails++;
            botReqs++;
            resolve();
        });

        req.on('timeout', () => {
            req.destroy();
            botFails++;
            botReqs++;
            resolve();
        });

        req.write(payload);
        req.end();
    });
}

async function sendTikTokBatch(batchDevices, aweme_id) {
    const devices = fs.existsSync('devices.txt') ? fs.readFileSync('devices.txt', 'utf-8').split('\n').filter(Boolean) : [];
    const promises = batchDevices.map(device => {
        const [did, iid, cdid, openudid] = device.split(':');
        return sendTikTokRequest(did, iid, cdid, openudid, aweme_id);
    });
    await Promise.all(promises);
}

async function startTikTokBot(aweme_id, target_views, original_views) {
    console.log('🚀 Starting TikTok Bot...');
    console.log(`🎯 Target: ${target_views} new views`);
    console.log(`📹 Original Views: ${original_views}`);
    console.log(`📹 Total Target: ${original_views + target_views}`);
    console.log(`📹 Video ID: ${aweme_id}`);
    
    const devices = fs.existsSync('devices.txt') ? fs.readFileSync('devices.txt', 'utf-8').split('\n').filter(Boolean) : [];
    const concurrency = 200;
    
    botRunning = true;
    botTargetViews = target_views;
    originalViews = original_views;
    botReqs = 0; botSuccess = 0; botFails = 0;
    currentVideoId = aweme_id;
    
    // Stats loop
    let lastReqs = botReqs;
    const statsInterval = setInterval(() => {
        botRps = ((botReqs - lastReqs) / 1.5).toFixed(1);
        botRpm = (botRps * 60).toFixed(1);
        lastReqs = botReqs;
        
        if (!botRunning) {
            clearInterval(statsInterval);
        }
    }, 1500);
    
    // Main bot loop
    while (botRunning && botSuccess < botTargetViews) {
        const batchDevices = [];
        for (let i = 0; i < concurrency && i < devices.length; i++) {
            batchDevices.push(devices[Math.floor(Math.random() * devices.length)]);
        }
        await sendTikTokBatch(batchDevices, aweme_id);
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    if (botSuccess >= botTargetViews) {
        console.log(`🎉 TikTok Bot Completed! Sent ${botSuccess} new views`);
        console.log(`📊 Total Views: ${original_views + botSuccess}`);
    }
    
    botRunning = false;
}

// ================= MIDDLEWARE =================
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ success: false, message: 'Access token required' });
    }
    
    jwt.verify(token, 'your-secret-key-123', (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: 'Invalid token' });
        }
        req.user = user;
        next();
    });
}

// ================= SERVER START =================
app.listen(PORT, () => {
    initDB();
    console.log(`🚀 Enhanced TikTok Bot Website Running!`);
    console.log(`📍 Port: ${PORT}`);
    console.log(`🌐 Login: http://localhost:${PORT}/`);
    console.log(`📊 Dashboard: http://localhost:${PORT}/dashboard`);
    console.log(`🤖 TikTok Bot: Ready with Real View Counting`);
    console.log(`🔐 Admin Key: YOUR_ADMIN_SECRET_123`);
});
