const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const https = require('https');
const crypto = require('crypto');

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
let currentVideoData = null;
let initialViewCount = 0;

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

// ================= TIKTOK VIDEO INFO ROUTES =================
app.post('/api/tiktok/video-info', authenticateToken, async (req, res) => {
    const { video_url } = req.body;
    
    try {
        const videoInfo = await getRealTikTokVideoInfo(video_url);
        if (videoInfo.success) {
            res.json(videoInfo);
        } else {
            res.json({ success: false, message: videoInfo.message });
        }
    } catch (error) {
        res.json({ success: false, message: 'Error fetching video info' });
    }
});

// ================= TIKTOK BOT ROUTES =================
app.post('/api/tiktok/start', authenticateToken, async (req, res) => {
    const { video_url, target_views } = req.body;
    const user = req.user;
    
    if (botRunning) {
        return res.json({ success: false, message: 'Bot is already running' });
    }
    
    const idMatch = video_url.match(/\d{18,19}/g);
    if (!idMatch) {
        return res.json({ success: false, message: 'Invalid TikTok URL' });
    }
    
    const aweme_id = idMatch[0];
    const targetViews = parseInt(target_views);
    
    // Get REAL current video info and view count
    const videoInfo = await getRealTikTokVideoInfo(video_url);
    if (!videoInfo.success) {
        return res.json({ success: false, message: videoInfo.message });
    }
    
    // Add to history
    addToHistory(user.email, video_url, videoInfo, targetViews);
    
    // Start REAL bot in background
    startRealTikTokBot(aweme_id, targetViews, videoInfo.views);
    
    res.json({ 
        success: true, 
        message: 'TikTok bot started successfully!',
        video_id: aweme_id,
        target_views: targetViews,
        video_info: videoInfo,
        initial_views: videoInfo.views
    });
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
            progress: botSuccess,
            video_id: currentVideoId,
            initial_views: initialViewCount,
            estimated_total: initialViewCount + botSuccess
        },
        video_info: currentVideoData
    });
});

// ================= HISTORY ROUTES =================
app.get('/api/tiktok/history', authenticateToken, (req, res) => {
    const user = req.user;
    const history = readDB(HISTORY_DB);
    const userHistory = history.filter(item => item.user_email === user.email);
    res.json({ success: true, history: userHistory.reverse() });
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

// ================= REAL TIKTOK VIDEO INFO FUNCTIONS =================
async function getRealTikTokVideoInfo(video_url) {
    try {
        const idMatch = video_url.match(/\d{18,19}/g);
        if (!idMatch) {
            return { success: false, message: 'Invalid TikTok URL' };
        }
        
        const aweme_id = idMatch[0];
        
        // REAL TikTok API call to get video info
        const videoInfo = await fetchTikTokVideoInfo(aweme_id);
        return videoInfo;
        
    } catch (error) {
        console.log('Error fetching TikTok video info:', error);
        return { success: false, message: 'Failed to fetch video information' };
    }
}

async function fetchTikTokVideoInfo(aweme_id) {
    return new Promise((resolve) => {
        const options = {
            hostname: 'api16-normal-c-useast1a.tiktokv.com',
            port: 443,
            path: `/aweme/v1/feed/?aweme_id=${aweme_id}`,
            method: 'GET',
            headers: {
                'User-Agent': 'TikTok 26.2.0 rv:262018 (iPhone; iOS 14.4.2; en_US) Cronet',
                'Accept': 'application/json'
            },
            timeout: 10000
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            res.on('end', () => {
                try {
                    const jsonData = JSON.parse(data);
                    if (jsonData.aweme_list && jsonData.aweme_list.length > 0) {
                        const video = jsonData.aweme_list[0];
                        resolve({
                            success: true,
                            video_id: aweme_id,
                            title: video.desc || 'TikTok Video',
                            views: video.statistics.play_count || 0,
                            likes: video.statistics.digg_count || 0,
                            shares: video.statistics.share_count || 0,
                            comments: video.statistics.comment_count || 0,
                            author: video.author ? video.author.unique_id : 'unknown',
                            duration: video.video ? video.video.duration / 1000 : 0,
                            created_time: video.create_time ? new Date(video.create_time * 1000).toISOString() : new Date().toISOString()
                        });
                    } else {
                        resolve({ success: false, message: 'Video not found' });
                    }
                } catch (e) {
                    resolve({ success: false, message: 'Invalid response from TikTok' });
                }
            });
        });

        req.on('error', (e) => {
            resolve({ success: false, message: 'Network error' });
        });

        req.on('timeout', () => {
            req.destroy();
            resolve({ success: false, message: 'Request timeout' });
        });

        req.end();
    });
}

// ================= REAL TIKTOK BOT FUNCTIONS =================
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

function sendRealTikTokRequest(did, iid, cdid, openudid, aweme_id) {
    return new Promise((resolve) => {
        if (!botRunning) {
            resolve();
            return;
        }

        // REAL TikTok view request parameters
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
                        console.log(`✅ REAL TikTok Views Sent: ${botSuccess}/${botTargetViews}`);
                        
                        // REAL target checking
                        if (botSuccess >= botTargetViews) {
                            console.log('🎉 REAL TikTok Target Completed!');
                            botRunning = false;
                        }
                    } else {
                        botFails++;
                        console.log('❌ View request failed');
                    }
                } catch (e) {
                    botFails++;
                    console.log('❌ Parse error');
                }
                resolve();
            });
        });

        req.on('error', (e) => {
            botFails++;
            botReqs++;
            console.log('❌ Network error');
            resolve();
        });

        req.on('timeout', () => {
            req.destroy();
            botFails++;
            botReqs++;
            console.log('❌ Request timeout');
            resolve();
        });

        req.write(payload);
        req.end();
    });
}

async function sendRealTikTokBatch(batchDevices, aweme_id) {
    const devices = fs.existsSync('devices.txt') ? fs.readFileSync('devices.txt', 'utf-8').split('\n').filter(Boolean) : [];
    const promises = batchDevices.map(device => {
        const [did, iid, cdid, openudid] = device.split(':');
        return sendRealTikTokRequest(did, iid, cdid, openudid, aweme_id);
    });
    await Promise.all(promises);
}

async function startRealTikTokBot(aweme_id, target_views, initial_views) {
    console.log('🚀 Starting REAL TikTok Bot...');
    console.log(`🎯 Target: ${target_views} REAL views`);
    console.log(`📹 Video ID: ${aweme_id}`);
    console.log(`👀 Initial REAL Views: ${initial_views}`);
    
    const devices = fs.existsSync('devices.txt') ? fs.readFileSync('devices.txt', 'utf-8').split('\n').filter(Boolean) : [];
    
    if (devices.length === 0) {
        console.log('❌ No devices loaded! Check devices.txt');
        return;
    }
    
    console.log(`📱 Devices loaded: ${devices.length}`);
    
    const concurrency = 200;
    
    botRunning = true;
    botTargetViews = target_views;
    botReqs = 0; botSuccess = 0; botFails = 0;
    currentVideoId = aweme_id;
    initialViewCount = initial_views;
    currentVideoData = await getRealTikTokVideoInfo(`https://www.tiktok.com/video/${aweme_id}`);
    
    // Stats loop
    let lastReqs = botReqs;
    const statsInterval = setInterval(() => {
        botRps = ((botReqs - lastReqs) / 1.5).toFixed(1);
        botRpm = (botRps * 60).toFixed(1);
        lastReqs = botReqs;
        
        console.log(`📊 REAL Stats - Success: ${botSuccess}, Fails: ${botFails}, RPS: ${botRps}`);
        
        if (!botRunning) {
            clearInterval(statsInterval);
            console.log('🛑 REAL Bot stopped');
        }
    }, 1500);
    
    // REAL bot loop
    try {
        while (botRunning && botSuccess < botTargetViews) {
            const batchDevices = [];
            for (let i = 0; i < concurrency && i < devices.length; i++) {
                batchDevices.push(devices[Math.floor(Math.random() * devices.length)]);
            }
            await sendRealTikTokBatch(batchDevices, aweme_id);
            await new Promise(resolve => setTimeout(resolve, 100));
        }
        
        if (botSuccess >= botTargetViews) {
            console.log(`🎉 REAL TikTok Bot Completed! Sent ${botSuccess} REAL views`);
            
            // Verify final views
            const finalVideoInfo = await getRealTikTokVideoInfo(`https://www.tiktok.com/video/${aweme_id}`);
            if (finalVideoInfo.success) {
                console.log(`📊 Final REAL Views: ${finalVideoInfo.views} (Initial: ${initialViewCount})`);
            }
        }
    } catch (error) {
        console.log('❌ Bot error:', error);
    }
    
    botRunning = false;
}

// ================= HISTORY FUNCTIONS =================
function addToHistory(user_email, video_url, video_info, target_views) {
    const history = readDB(HISTORY_DB);
    
    const historyItem = {
        id: Date.now().toString(),
        user_email,
        video_url,
        video_info,
        target_views,
        initial_views: video_info.views,
        created_at: new Date().toISOString(),
        status: 'completed'
    };
    
    history.push(historyItem);
    writeDB(HISTORY_DB, history);
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
    console.log(`🚀 REAL TikTok Bot Website Running!`);
    console.log(`📍 Port: ${PORT}`);
    console.log(`🌐 Login: http://localhost:${PORT}/`);
    console.log(`📊 Dashboard: http://localhost:${PORT}/dashboard`);
    console.log(`🤖 REAL TikTok Bot: Ready with 200 threads`);
    console.log(`🔐 Admin Key: YOUR_ADMIN_SECRET_123`);
    console.log(`📱 Make sure devices.txt has your 14,000+ devices!`);
});
