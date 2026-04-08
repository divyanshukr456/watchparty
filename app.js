/* ═══════════════════════════════════════════════════════
   WatchSync — Watch Party Application
   ═══════════════════════════════════════════════════════
   SECURITY:
   • End-to-end AES-256-GCM encrypted chat via Web Crypto API
   • PBKDF2 key derivation from room code
   • Input sanitization on all user data
   • No innerHTML with untrusted data — textContent only
   • Peer-to-peer via PeerJS WebRTC (no server sees messages)
   • Rate limiting on chat messages
   ═══════════════════════════════════════════════════════ */

(() => {
    'use strict';

    // ═══════════════════════════
    //  SECURITY UTILITIES
    // ═══════════════════════════

    /** Sanitize string input */
    function sanitize(str, maxLen = 200) {
        if (typeof str !== 'string') return '';
        return str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').trim().slice(0, maxLen);
    }

    /** Escape HTML for safe display */
    function escapeHtml(str) {
        if (typeof str !== 'string') return '';
        const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;' };
        return str.replace(/[&<>"']/g, c => map[c]);
    }

    /** Validate YouTube video ID */
    function extractVideoId(input) {
        const clean = sanitize(input, 300);
        // Patterns: youtu.be/ID, youtube.com/watch?v=ID, youtube.com/embed/ID
        const patterns = [
            /(?:youtu\.be\/)([a-zA-Z0-9_-]{11})/,
            /(?:youtube\.com\/watch\?.*v=)([a-zA-Z0-9_-]{11})/,
            /(?:youtube\.com\/embed\/)([a-zA-Z0-9_-]{11})/,
            /(?:youtube\.com\/v\/)([a-zA-Z0-9_-]{11})/,
            /^([a-zA-Z0-9_-]{11})$/ // bare video ID
        ];
        for (const p of patterns) {
            const m = clean.match(p);
            if (m) return m[1];
        }
        return null;
    }

    /** Generate room code: XXXX-XXXX */
    function generateRoomCode() {
        const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no ambiguous chars
        let code = '';
        const arr = crypto.getRandomValues(new Uint8Array(8));
        for (let i = 0; i < 8; i++) {
            if (i === 4) code += '-';
            code += chars[arr[i] % chars.length];
        }
        return code;
    }

    /** Rate limiter */
    function createRateLimiter(max, windowMs) {
        const timestamps = [];
        return {
            check() {
                const now = Date.now();
                while (timestamps.length && timestamps[0] <= now - windowMs) timestamps.shift();
                if (timestamps.length >= max) return false;
                timestamps.push(now);
                return true;
            }
        };
    }
    const chatLimiter = createRateLimiter(10, 5000); // 10 msgs per 5s

    /** Safe element creator */
    function el(tag, attrs = {}, text = '') {
        const e = document.createElement(tag);
        for (const [k, v] of Object.entries(attrs)) {
            if (k === 'className') e.className = v;
            else if (k === 'dataset') Object.entries(v).forEach(([dk,dv]) => e.dataset[dk] = dv);
            else e.setAttribute(k, v);
        }
        if (text) e.textContent = text;
        return e;
    }

    // ═══════════════════════════
    //  ENCRYPTION (AES-256-GCM)
    // ═══════════════════════════

    let cryptoKey = null;
    const SALT = new TextEncoder().encode('WatchSync-E2E-v1');

    async function deriveKey(roomCode) {
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(roomCode),
            'PBKDF2',
            false,
            ['deriveKey']
        );
        cryptoKey = await crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt: SALT, iterations: 250000, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    async function encryptMessage(plaintext) {
        if (!cryptoKey) throw new Error('No encryption key');
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(plaintext);
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            cryptoKey,
            encoded
        );
        return {
            ct: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
            iv: btoa(String.fromCharCode(...iv))
        };
    }

    async function decryptMessage(ct, ivStr) {
        if (!cryptoKey) throw new Error('No decryption key');
        try {
            const ciphertext = Uint8Array.from(atob(ct), c => c.charCodeAt(0));
            const iv = Uint8Array.from(atob(ivStr), c => c.charCodeAt(0));
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                cryptoKey,
                ciphertext
            );
            return new TextDecoder().decode(decrypted);
        } catch {
            return '[Decryption failed]';
        }
    }

    // ═══════════════════════════
    //  DOM REFERENCES
    // ═══════════════════════════

    const $ = s => document.querySelector(s);
    const $$ = s => document.querySelectorAll(s);

    const dom = {
        // Screens
        screenLanding: $('#screen-landing'),
        screenLobby: $('#screen-lobby'),
        screenRoom: $('#screen-room'),
        // Landing
        createName: $('#create-name'),
        joinName: $('#join-name'),
        joinCode: $('#join-code'),
        btnCreate: $('#btn-create-room'),
        btnJoin: $('#btn-join-room'),
        sizeBtns: $$('.size-btn'),
        // Lobby
        lobbyCode: $('#lobby-room-code'),
        btnCopy: $('#btn-copy-code'),
        btnLeaveLobby: $('#btn-leave-lobby'),
        playerSlots: $('#player-slots'),
        playerCount: $('#lobby-player-count'),
        maxPlayers: $('#lobby-max-players'),
        lobbyWaiting: $('#lobby-waiting'),
        btnStart: $('#btn-start-party'),
        // Room
        roomCodeTag: $('#room-code-tag'),
        roomActiveCount: $('#room-active-count'),
        btnLeaveRoom: $('#btn-leave-room'),
        videoUrlInput: $('#video-url-input'),
        btnLoadVideo: $('#btn-load-video'),
        videoPlaceholder: $('#video-placeholder'),
        ytPlayerWrapper: $('#yt-player-wrapper'),
        chatMessages: $('#chat-messages'),
        chatInput: $('#chat-input'),
        btnSend: $('#btn-send'),
        videoControls: $('#video-controls'),
        // Toast
        toastContainer: $('#toast-container')
    };

    // ═══════════════════════════
    //  STATE
    // ═══════════════════════════

    const state = {
        roomCode: '',
        myName: '',
        myPeerId: '',
        isHost: false,
        maxPlayers: 3,
        players: [],       // [{name, peerId, conn}]
        peer: null,         // PeerJS instance
        connections: [],    // DataConnection[]
        ytPlayer: null,
        currentVideoId: '',
        inRoom: false
    };

    // ═══════════════════════════
    //  TOAST
    // ═══════════════════════════

    function toast(msg, type = 'info') {
        const t = el('div', { className: `toast ${type}` });
        const icons = { success: 'fa-check-circle', error: 'fa-exclamation-circle', info: 'fa-info-circle' };
        const i = el('i', { className: `fas ${icons[type] || icons.info}` });
        const s = el('span', {}, sanitize(msg, 120));
        t.appendChild(i); t.appendChild(s);
        dom.toastContainer.appendChild(t);
        setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 300); }, 3500);
    }

    // ═══════════════════════════
    //  SCREEN MANAGEMENT
    // ═══════════════════════════

    function showScreen(name) {
        $$('.screen').forEach(s => s.classList.remove('active'));
        const screen = $(`#screen-${name}`);
        if (screen) screen.classList.add('active');
    }

    // ═══════════════════════════
    //  PEER SETUP (WebRTC)
    // ═══════════════════════════

    function createPeer(id) {
        return new Promise((resolve, reject) => {
            const peer = new Peer(id, {
                debug: 0,
                config: {
                    iceServers: [
                        { urls: 'stun:stun.l.google.com:19302' },
                        { urls: 'stun:stun1.l.google.com:19302' }
                    ]
                }
            });
            peer.on('open', () => resolve(peer));
            peer.on('error', (err) => {
                console.error('Peer error:', err);
                if (err.type === 'unavailable-id') {
                    reject(new Error('Room code already in use. Try again.'));
                } else if (err.type === 'peer-unavailable') {
                    reject(new Error('Room not found. Check the code.'));
                } else {
                    reject(err);
                }
            });
            // Timeout
            setTimeout(() => reject(new Error('Connection timed out')), 15000);
        });
    }

    function makePeerId(code, suffix) {
        return `watchsync-${code.replace('-', '')}-${suffix}`;
    }

    // ═══════════════════════════
    //  MESSAGE PROTOCOL
    // ═══════════════════════════

    // Types: chat, video_sync, player_join, player_leave, player_list, start_party

    function broadcast(data) {
        const str = JSON.stringify(data);
        state.connections.forEach(conn => {
            if (conn.open) {
                try { conn.send(str); } catch (e) { console.warn('Send failed:', e); }
            }
        });
    }

    function sendTo(conn, data) {
        if (conn && conn.open) {
            try { conn.send(JSON.stringify(data)); } catch (e) { console.warn('Send failed:', e); }
        }
    }

    async function handleMessage(data, fromConn) {
        if (!data || !data.type) return;

        switch (data.type) {
            case 'chat':
                await handleChatReceived(data);
                // Host relays to all other peers
                if (state.isHost) {
                    const str = JSON.stringify(data);
                    state.connections.forEach(c => {
                        if (c !== fromConn && c.open) {
                            try { c.send(str); } catch(_) {}
                        }
                    });
                }
                break;
            case 'video_sync':
                handleVideoSync(data);
                if (state.isHost) {
                    // Relay sync from host to all
                }
                break;
            case 'video_load':
                handleVideoLoad(data);
                break;
            case 'player_join':
                handlePlayerJoin(data, fromConn);
                break;
            case 'player_list':
                handlePlayerList(data);
                break;
            case 'start_party':
                enterRoom();
                break;
            case 'player_leave':
                handlePlayerLeave(data);
                break;
        }
    }

    function setupConnection(conn) {
        state.connections.push(conn);
        conn.on('data', async (raw) => {
            try {
                const data = typeof raw === 'string' ? JSON.parse(raw) : raw;
                await handleMessage(data, conn);
            } catch (e) {
                console.warn('Invalid message received:', e);
            }
        });
        conn.on('close', () => {
            state.connections = state.connections.filter(c => c !== conn);
            const player = state.players.find(p => p.conn === conn);
            if (player) {
                state.players = state.players.filter(p => p !== player);
                if (state.isHost) {
                    broadcast({ type: 'player_leave', name: player.name, peerId: player.peerId });
                }
                addChatEvent(`${sanitize(player.name, 20)} left the room`);
                updatePlayerUI();
            }
        });
        conn.on('error', (e) => console.warn('Connection error:', e));
    }

    // ═══════════════════════════
    //  CREATE ROOM
    // ═══════════════════════════

    dom.btnCreate.addEventListener('click', async () => {
        const name = sanitize(dom.createName.value, 20);
        if (!name) { toast('Please enter your name', 'error'); return; }
        if (name.length < 2) { toast('Name must be at least 2 characters', 'error'); return; }

        const selectedSize = document.querySelector('.size-btn.active');
        state.maxPlayers = parseInt(selectedSize?.dataset.size || '3');
        state.myName = name;
        state.roomCode = generateRoomCode();
        state.isHost = true;

        dom.btnCreate.disabled = true;
        dom.btnCreate.textContent = 'Creating...';

        try {
            const peerId = makePeerId(state.roomCode, 'host');
            state.peer = await createPeer(peerId);
            state.myPeerId = peerId;

            // Derive encryption key from room code
            await deriveKey(state.roomCode);

            // Listen for incoming connections
            state.peer.on('connection', (conn) => {
                conn.on('open', () => {
                    setupConnection(conn);
                });
            });

            // Add self to players
            state.players = [{ name: state.myName, peerId: state.myPeerId, conn: null, isHost: true }];

            showLobby();
        } catch (e) {
            toast(e.message || 'Failed to create room', 'error');
        } finally {
            dom.btnCreate.disabled = false;
            dom.btnCreate.innerHTML = '<i class="fas fa-rocket"></i> Create Room';
        }
    });

    // ═══════════════════════════
    //  JOIN ROOM
    // ═══════════════════════════

    dom.btnJoin.addEventListener('click', async () => {
        const name = sanitize(dom.joinName.value, 20);
        const code = sanitize(dom.joinCode.value, 9).toUpperCase();

        if (!name || name.length < 2) { toast('Please enter your name (min 2 chars)', 'error'); return; }
        if (!code || code.length < 9 || !/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(code)) {
            toast('Enter a valid room code (e.g. ABCD-1234)', 'error'); return;
        }

        state.myName = name;
        state.roomCode = code;
        state.isHost = false;

        dom.btnJoin.disabled = true;
        dom.btnJoin.textContent = 'Joining...';

        try {
            // Generate unique peer ID
            const randomSuffix = crypto.getRandomValues(new Uint8Array(4));
            const suffix = Array.from(randomSuffix).map(b => b.toString(16).padStart(2, '0')).join('');
            const peerId = makePeerId(state.roomCode, suffix);
            state.peer = await createPeer(peerId);
            state.myPeerId = peerId;

            // Derive encryption key
            await deriveKey(state.roomCode);

            // Connect to host
            const hostPeerId = makePeerId(state.roomCode, 'host');
            const conn = state.peer.connect(hostPeerId, { reliable: true });

            conn.on('open', () => {
                setupConnection(conn);
                // Announce ourselves
                sendTo(conn, {
                    type: 'player_join',
                    name: state.myName,
                    peerId: state.myPeerId
                });
            });

            conn.on('error', (e) => {
                toast('Could not connect to room', 'error');
                console.error('Join error:', e);
            });

            // Wait a moment then show lobby
            setTimeout(() => {
                if (state.connections.length > 0) {
                    showLobby();
                } else {
                    toast('Room not found or unavailable', 'error');
                    cleanupPeer();
                }
            }, 3000);

        } catch (e) {
            toast(e.message || 'Failed to join room', 'error');
        } finally {
            dom.btnJoin.disabled = false;
            dom.btnJoin.innerHTML = '<i class="fas fa-door-open"></i> Join Room';
        }
    });

    // ═══════════════════════════
    //  PLAYER JOIN/LIST HANDLING
    // ═══════════════════════════

    function handlePlayerJoin(data, fromConn) {
        if (!state.isHost) return;

        const name = sanitize(data.name, 20);
        const peerId = sanitize(data.peerId, 80);

        // Check room capacity
        if (state.players.length >= state.maxPlayers) {
            sendTo(fromConn, { type: 'error', message: 'Room is full' });
            fromConn.close();
            return;
        }

        // Check duplicate
        if (state.players.find(p => p.peerId === peerId)) return;

        // Add player
        const player = { name, peerId, conn: fromConn, isHost: false };
        state.players.push(player);

        addChatEvent(`${name} joined the room`);

        // Send full player list to everyone
        broadcastPlayerList();
        updatePlayerUI();
    }

    function broadcastPlayerList() {
        const list = state.players.map(p => ({
            name: p.name,
            peerId: p.peerId,
            isHost: p.isHost || false
        }));
        broadcast({
            type: 'player_list',
            players: list,
            maxPlayers: state.maxPlayers
        });
    }

    function handlePlayerList(data) {
        if (state.isHost) return; // Host manages its own list
        state.players = (data.players || []).map(p => ({
            name: sanitize(p.name, 20),
            peerId: sanitize(p.peerId, 80),
            isHost: !!p.isHost,
            conn: null
        }));
        state.maxPlayers = data.maxPlayers || 3;

        // Add self if not in list
        if (!state.players.find(p => p.peerId === state.myPeerId)) {
            state.players.push({ name: state.myName, peerId: state.myPeerId, isHost: false, conn: null });
        }
        updatePlayerUI();
    }

    function handlePlayerLeave(data) {
        const name = sanitize(data.name, 20);
        state.players = state.players.filter(p => p.peerId !== data.peerId);
        addChatEvent(`${name} left the room`);
        updatePlayerUI();
    }

    // ═══════════════════════════
    //  LOBBY
    // ═══════════════════════════

    function showLobby() {
        showScreen('lobby');
        dom.lobbyCode.textContent = state.roomCode;
        dom.maxPlayers.textContent = state.maxPlayers;
        updatePlayerUI();
    }

    function updatePlayerUI() {
        // In lobby
        dom.playerSlots.textContent = '';
        dom.playerCount.textContent = state.players.length;
        dom.maxPlayers.textContent = state.maxPlayers;

        for (let i = 0; i < state.maxPlayers; i++) {
            const player = state.players[i];
            const slot = el('div', { className: `player-slot${player ? ' filled' : ''}${player?.isHost ? ' host' : ''}` });
            const avatar = el('div', { className: 'player-avatar' });

            if (player) {
                avatar.textContent = player.name.charAt(0).toUpperCase();
                const nameLbl = el('div', { className: 'player-slot-name' }, player.name);
                slot.appendChild(avatar);
                slot.appendChild(nameLbl);
                if (player.isHost) {
                    const hostBadge = el('div', { className: 'player-slot-name' }, '⭐ Host');
                    slot.appendChild(hostBadge);
                }
            } else {
                const icon = el('i', { className: 'fas fa-user-plus' });
                avatar.appendChild(icon);
                const nameLbl = el('div', { className: 'player-slot-name' }, 'Empty');
                slot.appendChild(avatar);
                slot.appendChild(nameLbl);
            }
            dom.playerSlots.appendChild(slot);
        }

        // Enable start button if at least 2 players (host only)
        if (state.isHost) {
            dom.btnStart.disabled = state.players.length < 2;
            dom.btnStart.style.display = '';
        } else {
            dom.btnStart.style.display = 'none';
        }

        // Update room screen counts
        dom.roomActiveCount.textContent = state.players.length;

        // Show/hide waiting
        dom.lobbyWaiting.style.display = state.players.length < state.maxPlayers ? 'flex' : 'none';
    }

    // Copy code
    dom.btnCopy.addEventListener('click', () => {
        navigator.clipboard.writeText(state.roomCode).then(() => {
            toast('Room code copied!', 'success');
        }).catch(() => {
            // Fallback
            const ta = el('textarea');
            ta.value = state.roomCode;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            ta.remove();
            toast('Room code copied!', 'success');
        });
    });

    // Start party
    dom.btnStart.addEventListener('click', () => {
        if (!state.isHost) return;
        if (state.players.length < 2) { toast('Need at least 2 people', 'error'); return; }
        broadcast({ type: 'start_party' });
        enterRoom();
    });

    // Leave buttons
    dom.btnLeaveLobby.addEventListener('click', leaveRoom);
    dom.btnLeaveRoom.addEventListener('click', leaveRoom);

    function leaveRoom() {
        if (state.isHost) {
            broadcast({ type: 'player_leave', name: state.myName, peerId: state.myPeerId });
        }
        cleanupPeer();
        state.players = [];
        state.connections = [];
        state.inRoom = false;
        state.currentVideoId = '';
        showScreen('landing');
        toast('You left the room', 'info');
    }

    function cleanupPeer() {
        if (state.peer) {
            try { state.peer.destroy(); } catch(_) {}
            state.peer = null;
        }
    }

    // ═══════════════════════════
    //  ROOM (Watch Party)
    // ═══════════════════════════

    function enterRoom() {
        state.inRoom = true;
        showScreen('room');
        dom.roomCodeTag.textContent = state.roomCode;
        updatePlayerUI();

        // Only host can load videos
        if (!state.isHost) {
            dom.videoControls.style.display = 'none';
        }

        addChatEvent('Watch party started! 🎉');
    }

    // ═══════════════════════════
    //  YOUTUBE PLAYER
    // ═══════════════════════════

    let ytReady = false;
    let ytPlayerObj = null;

    // YouTube API calls this when ready
    window.onYouTubeIframeAPIReady = () => {
        ytReady = true;
    };

    function loadVideo(videoId) {
        if (!videoId) return;
        state.currentVideoId = videoId;
        dom.videoPlaceholder.style.display = 'none';
        dom.ytPlayerWrapper.style.display = 'block';

        if (ytPlayerObj) {
            ytPlayerObj.loadVideoById(videoId);
        } else if (ytReady) {
            ytPlayerObj = new YT.Player('yt-player', {
                videoId: videoId,
                playerVars: {
                    autoplay: 1,
                    modestbranding: 1,
                    rel: 0,
                    fs: 1
                },
                events: {
                    onStateChange: onPlayerStateChange,
                    onReady: () => { ytPlayerObj.playVideo(); }
                }
            });
        } else {
            // YouTube API not ready yet
            setTimeout(() => loadVideo(videoId), 500);
        }
    }

    function onPlayerStateChange(event) {
        if (!state.isHost) return;
        // Sync state to guests
        const playerState = event.data;
        if (playerState === YT.PlayerState.PLAYING) {
            broadcast({ type: 'video_sync', action: 'play', time: ytPlayerObj.getCurrentTime() });
        } else if (playerState === YT.PlayerState.PAUSED) {
            broadcast({ type: 'video_sync', action: 'pause', time: ytPlayerObj.getCurrentTime() });
        }
    }

    // Periodic sync from host
    setInterval(() => {
        if (state.isHost && state.inRoom && ytPlayerObj && ytPlayerObj.getCurrentTime) {
            try {
                const playerState = ytPlayerObj.getPlayerState();
                if (playerState === YT.PlayerState.PLAYING) {
                    broadcast({
                        type: 'video_sync',
                        action: 'play',
                        time: ytPlayerObj.getCurrentTime()
                    });
                }
            } catch(_) {}
        }
    }, 5000);

    function handleVideoSync(data) {
        if (state.isHost) return; // Host doesn't receive sync from itself
        if (!ytPlayerObj) return;

        try {
            const currentTime = ytPlayerObj.getCurrentTime();
            const diff = Math.abs(currentTime - data.time);

            if (data.action === 'play') {
                if (diff > 2) ytPlayerObj.seekTo(data.time, true);
                ytPlayerObj.playVideo();
            } else if (data.action === 'pause') {
                ytPlayerObj.seekTo(data.time, true);
                ytPlayerObj.pauseVideo();
            } else if (data.action === 'seek') {
                ytPlayerObj.seekTo(data.time, true);
            }
        } catch(e) { console.warn('Sync error:', e); }
    }

    function handleVideoLoad(data) {
        const videoId = extractVideoId(data.videoId || '');
        if (videoId) {
            loadVideo(videoId);
            addChatEvent(`Now playing a new video 🎬`);
        }
    }

    // Load video button
    dom.btnLoadVideo.addEventListener('click', () => {
        if (!state.isHost) { toast('Only the host can load videos', 'error'); return; }
        const videoId = extractVideoId(dom.videoUrlInput.value);
        if (!videoId) { toast('Invalid YouTube URL', 'error'); return; }

        loadVideo(videoId);
        broadcast({ type: 'video_load', videoId: videoId });
        dom.videoUrlInput.value = '';
        addChatEvent('Host loaded a new video 🎬');
    });

    dom.videoUrlInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') dom.btnLoadVideo.click();
    });

    // ═══════════════════════════
    //  CHAT (Encrypted)
    // ═══════════════════════════

    async function sendChat() {
        const raw = dom.chatInput.value.trim();
        if (!raw) return;
        const text = sanitize(raw, 500);
        if (!text) return;

        // Rate limit
        if (!chatLimiter.check()) {
            toast('Slow down! Too many messages.', 'error');
            return;
        }

        dom.chatInput.value = '';

        try {
            const { ct, iv } = await encryptMessage(text);
            const msg = {
                type: 'chat',
                ct, iv,
                sender: state.myName,
                timestamp: Date.now()
            };

            // Show locally
            addChatMessage(state.myName, text, msg.timestamp, true);

            // Send
            if (state.isHost) {
                broadcast(msg);
            } else {
                // Send to host (who relays)
                state.connections.forEach(c => {
                    if (c.open) sendTo(c, msg);
                });
            }
        } catch (e) {
            toast('Failed to encrypt message', 'error');
            console.error('Encrypt error:', e);
        }
    }

    async function handleChatReceived(data) {
        const sender = sanitize(data.sender, 20);
        if (sender === state.myName) return; // Don't show own messages twice

        try {
            const text = await decryptMessage(data.ct, data.iv);
            addChatMessage(sender, text, data.timestamp || Date.now(), false);
        } catch (e) {
            addChatMessage(sender, '[Encrypted message]', data.timestamp || Date.now(), false);
        }
    }

    function addChatMessage(sender, text, timestamp, isSelf) {
        const msgDiv = el('div', { className: `chat-msg${isSelf ? ' self' : ''}` });

        const header = el('div', { className: 'chat-msg-header' });
        const nameSpan = el('span', { className: 'chat-msg-name' }, sender);
        const timeSpan = el('span', { className: 'chat-msg-time' }, formatTime(timestamp));
        header.appendChild(nameSpan);
        header.appendChild(timeSpan);
        msgDiv.appendChild(header);

        const body = el('div', { className: 'chat-msg-body' }, text);
        msgDiv.appendChild(body);

        dom.chatMessages.appendChild(msgDiv);
        dom.chatMessages.scrollTop = dom.chatMessages.scrollHeight;
    }

    function addChatEvent(text) {
        const ev = el('div', { className: 'chat-event' });
        const icon = el('i', { className: 'fas fa-circle', style: 'font-size:0.35rem;vertical-align:middle;' });
        ev.appendChild(icon);
        ev.appendChild(document.createTextNode(' ' + sanitize(text, 100)));
        dom.chatMessages.appendChild(ev);
        dom.chatMessages.scrollTop = dom.chatMessages.scrollHeight;
    }

    function formatTime(ts) {
        const d = new Date(ts);
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }

    // Chat send
    dom.btnSend.addEventListener('click', sendChat);
    dom.chatInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendChat();
        }
    });

    // ═══════════════════════════
    //  SIZE PICKER
    // ═══════════════════════════

    dom.sizeBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            dom.sizeBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
        });
    });

    // ═══════════════════════════
    //  INIT
    // ═══════════════════════════

    showScreen('landing');

    // Warn before leaving
    window.addEventListener('beforeunload', (e) => {
        if (state.inRoom || state.connections.length > 0) {
            e.preventDefault();
            e.returnValue = '';
        }
    });

})();
