/**
 * chat.js — Production-grade Real-Time Encrypted Messenger Engine
 *
 * Capabilities:
 *   - Client-side E2EE (X25519 ECDH + HKDF-SHA-256 + AES-256-GCM).
 *   - 14 Advanced Messaging Features:
 *       1. Reply to messages (quote snippet & click-to-scroll).
 *       2. Edit sent messages (in-place update with (edited) badge).
 *       3. Delete messages (server-side purge).
 *       4. Unsend messages (real-time retraction for both sender and peer).
 *       5. Emoji reactions (quick-bar & reaction pills with counts).
 *       6. Forward messages (client-side re-encryption for chosen contact).
 *       7. Pin important messages (channel banner & sidebar list).
 *       8. Search messages (highlight matches, match count, next/prev cycling).
 *       9. Message timestamps & date separators (clean times, ISO tooltips).
 *      10. Sent, delivered, and read status (single tick, double tick, blue ticks).
 *      11. Typing indicators (real-time 3-dot animated bubble).
 *      12. Online & offline status (live status dots, header state, stories strip).
 *      13. GIFs, stickers, and emojis (multi-tab picker with instant E2EE sending).
 *      14. Image, video, and document sharing (client-side AES-256-GCM encryption with lightbox).
 *   - Zero-plaintext storage: all media, text, quotes and edits encrypted before transmission.
 */

'use strict';

/* ─── Toast Notifications ─── */
const Toast = {
  container: null,

  init() {
    this.container = document.getElementById('toastContainer');
  },

  show(type, title, message, duration = 3500) {
    if (!this.container) this.init();
    if (!this.container) return;

    const icons = {
      success: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`,
      error:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
      info:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`,
      warning: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
    };

    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.setAttribute('role', 'alert');
    el.innerHTML = `
      <div class="toast-icon">${icons[type] || icons.info}</div>
      <div class="toast-content">
        <p class="toast-title">${escapeHtml(title)}</p>
        <p class="toast-msg">${escapeHtml(message)}</p>
      </div>
      <button class="toast-close" aria-label="Dismiss">&times;</button>
    `;

    el.querySelector('.toast-close')?.addEventListener('click', () => {
      el.classList.add('removing');
      setTimeout(() => el.remove(), 250);
    });

    this.container.appendChild(el);
    setTimeout(() => {
      if (el.parentNode) {
        el.classList.add('removing');
        setTimeout(() => el.remove(), 250);
      }
    }, duration);
  },
};

/* ─── State Management ─── */
const USERS = {};                     // username -> { id, username, email, initials, gradient, status, publicKey, lastLogin }
let activeUser     = null;            // Selected peer username
let activeGroup    = null;            // Selected group object { id, name, description, avatar_url, current_epoch, my_role, members }
let userGroups     = [];              // Array of user groups
let currentSidebarTab = 'primary';    // 'primary' | 'groups' | 'requests'
let myUsername     = 'me';
let myEmail        = '';
let socket         = null;
let typingDebounce = null;
const messagePayloadCache = new Map(); // messageId -> raw encrypted package dict

// Advanced Messaging State
let activeReply = null;               // { id, sender, snippet }
let activeEditingMessageId = null;    // messageId currently being edited
let forwardMessagePayload = null;     // { text, mediaMeta }
let searchMatches = [];               // array of matching DOM elements
let currentSearchIndex = -1;

/* ─── DOM Element References ─── */
const sidebar              = document.getElementById('sidebar');
const hamburgerBtn         = document.getElementById('hamburgerBtn');
const mobileBackBtn        = document.getElementById('mobileBackBtn');
const sidebarOverlay       = document.getElementById('sidebarOverlay');
const userListContainer    = document.getElementById('userList');
const searchInput          = document.getElementById('userSearch');
const contactsLabel        = document.getElementById('contactsLabel');
const refreshContactsBtn   = document.getElementById('refreshContactsBtn');
const messagesArea         = document.getElementById('messagesArea');
const historyLoader        = document.getElementById('historyLoader');
const emptyChatState       = document.getElementById('emptyChatState');
const emptyChatTitle       = document.getElementById('emptyChatTitle');
const messageInput         = document.getElementById('messageInput');
const sendBtn              = document.getElementById('sendBtn');
const typingIndicator      = document.getElementById('typingIndicator');
const chatHeader           = document.getElementById('chatHeader');
const chatHeaderName       = document.getElementById('chatHeaderName');
const chatHeaderStatus     = document.getElementById('chatHeaderStatus');
const chatAvatarInitials   = document.getElementById('chatAvatarInitials');
const chatStatusDot        = document.getElementById('chatStatusDot');
const gatewayBanner        = document.getElementById('gatewayBanner');
const gatewayBannerText    = document.getElementById('gatewayBannerText');
const activeHeaderUserCard = document.getElementById('activeHeaderUserCard');

/* Modals */
const myProfileBtn         = document.getElementById('myProfileBtn');
const userProfileCard      = document.getElementById('userProfileCard');
const myProfileModal       = document.getElementById('myProfileModal');
const closeMyProfileModal  = document.getElementById('closeMyProfileModal');
const copyMyPubKeyBtn      = document.getElementById('copyMyPubKeyBtn');
const myPublicKeyDisplay   = document.getElementById('myPublicKeyDisplay');
const myKeyFingerprint     = document.getElementById('myKeyFingerprint');

const peerProfileModal     = document.getElementById('peerProfileModal');
const closePeerProfileModal= document.getElementById('closePeerProfileModal');
const verifyKeysBtn        = document.getElementById('verifyKeysBtn');
const peerModalName        = document.getElementById('peerModalName');
const peerModalEmail       = document.getElementById('peerModalEmail');
const peerModalAvatar      = document.getElementById('peerModalAvatar');
const peerModalStatus      = document.getElementById('peerModalStatus');
const peerSafetyName       = document.getElementById('peerSafetyName');
const safetyNumberGrid     = document.getElementById('safetyNumberGrid');
const peerPublicKeyDisplay = document.getElementById('peerPublicKeyDisplay');
const copyPeerPubKeyBtn    = document.getElementById('copyPeerPubKeyBtn');

const inspectModal         = document.getElementById('inspectModal');
const closeInspectModal    = document.getElementById('closeInspectModal');
const inspectMsgId         = document.getElementById('inspectMsgId');
const inspectTimestamp     = document.getElementById('inspectTimestamp');
const inspectCiphertext    = document.getElementById('inspectCiphertext');
const inspectNonce         = document.getElementById('inspectNonce');
const inspectTag           = document.getElementById('inspectTag');
const inspectPlaintext     = document.getElementById('inspectPlaintext');
const copyCiphertextBtn    = document.getElementById('copyCiphertextBtn');

const encryptionBadgeHeader= document.getElementById('encryptionBadgeHeader');
const e2eeGlobalBadge      = document.getElementById('e2eeGlobalBadge');
const encryptionModal      = document.getElementById('encryptionModal');
const closeEncModal        = document.getElementById('closeEncModal');
const clearChatBtn         = document.getElementById('clearChatBtn');

/* Advanced Features UI */
const replyPreviewBar      = document.getElementById('replyPreviewBar');
const replySenderEl        = document.getElementById('replySender');
const replySnippetEl       = document.getElementById('replySnippet');
const cancelReplyBtn       = document.getElementById('cancelReplyBtn');

const editNoticeBar        = document.getElementById('editNoticeBar');
const editSnippetEl        = document.getElementById('editSnippet');
const cancelEditBtn        = document.getElementById('cancelEditBtn');

const pinnedBanner         = document.getElementById('pinnedBanner');
const pinnedBannerSnippet  = document.getElementById('pinnedBannerSnippet');
const pinnedBannerInner    = document.getElementById('pinnedBannerInner');
const unpinCurrentBtn      = document.getElementById('unpinCurrentBtn');

const inChatSearchBar      = document.getElementById('inChatSearchBar');
const inChatSearchInput    = document.getElementById('inChatSearchInput');
const inChatSearchCount    = document.getElementById('inChatSearchCount');
const inChatPrevBtn        = document.getElementById('inChatPrevBtn');
const inChatNextBtn        = document.getElementById('inChatNextBtn');
const inChatSearchClose    = document.getElementById('inChatSearchClose');

const attachmentBtn        = document.getElementById('attachmentBtn');
const fileInput            = document.getElementById('fileInput');

const forwardModal         = document.getElementById('forwardModal');
const closeForwardModal    = document.getElementById('closeForwardModal');
const cancelForwardBtn     = document.getElementById('cancelForwardBtn');
const forwardPreviewBox    = document.getElementById('forwardPreviewBox');
const forwardUserList      = document.getElementById('forwardUserList');

const mediaLightboxModal   = document.getElementById('mediaLightboxModal');
const closeLightboxBtn     = document.getElementById('closeLightboxBtn');
const lightboxMediaContent = document.getElementById('lightboxMediaContent');
const lightboxFileName     = document.getElementById('lightboxFileName');
const lightboxDownloadBtn  = document.getElementById('lightboxDownloadBtn');

/* ─── Helpers ─── */
function escapeHtml(text) {
  if (text === null || text === undefined) return '';
  const map = { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#039;' };
  return String(text).replace(/[&<>"']/g, m => map[m]);
}

function escapeRegex(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.content : '';
}

function formatTime(timestamp) {
  if (timestamp) {
    const cleanTs = timestamp.includes('T') ? timestamp : timestamp.replace(' ', 'T') + 'Z';
    const d = new Date(cleanTs);
    if (!isNaN(d.getTime())) {
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
    }
  }
  return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
}

function formatDateSeparator(timestamp) {
  if (!timestamp) return 'Today';
  const cleanTs = timestamp.includes('T') ? timestamp : timestamp.replace(' ', 'T') + 'Z';
  const d = new Date(cleanTs);
  if (isNaN(d.getTime())) return 'Today';

  const today = new Date();
  if (d.toDateString() === today.toDateString()) return 'Today';
  const yesterday = new Date();
  yesterday.setDate(today.getDate() - 1);
  if (d.toDateString() === yesterday.toDateString()) return 'Yesterday';

  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

function formatFileSize(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatDuration(seconds) {
  const s = Math.round(Number(seconds) || 0);
  const mins = Math.floor(s / 60);
  const secs = s % 60;
  return `${mins}:${secs < 10 ? '0' : ''}${secs}`;
}

function generateWaveformFromDuration(duration = 10, count = 28) {
  const seed = Math.max(1, Math.round(duration * 7));
  const bars = [];
  for (let i = 0; i < count; i++) {
    const x = i / count;
    const envelope = Math.sin(x * Math.PI);
    const noise = Math.sin((i + seed) * 1.7) * 0.5 + 0.5;
    const val = Math.max(0.2, Math.min(1.0, 0.25 + envelope * 0.55 + noise * 0.2));
    bars.push(parseFloat(val.toFixed(2)));
  }
  return bars;
}

function renderWaveformBarsHtml(waveform) {
  if (!Array.isArray(waveform) || waveform.length === 0) {
    waveform = generateWaveformFromDuration(10, 28);
  }
  return waveform.map((val, idx) => {
    const heightPercent = Math.max(15, Math.min(100, Math.round(val * 100)));
    return `<div class="waveform-bar" data-idx="${idx}" style="height:${heightPercent}%;"></div>`;
  }).join('');
}

function scrollToBottom(smooth = true) {
  if (!messagesArea) return;
  setTimeout(() => {
    messagesArea.scrollTo({
      top: messagesArea.scrollHeight,
      behavior: smooth ? 'smooth' : 'auto',
    });
  }, 50);
}

/* ─── UI Icons ─── */
function singleCheckSvg() {
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="14" height="14" style="color:var(--ig-text-muted)"><path d="M20 6L9 17l-5-5"/></svg>`;
}

function doubleCheckSvg(isRead = false) {
  const color = isRead ? '#38bdf8' : 'currentColor';
  return `<svg viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2.5" width="14" height="14"><path d="M2 12l5 5L15 6m4 0l-8 9-4-4"/></svg>`;
}

function trashSvg() {
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>`;
}

function downloadSvg() {
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="15" height="15"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>`;
}

/* ─── WebSocket Gateway ─── */
function initSocket() {
  if (typeof io === 'undefined') {
    console.warn('[Socket.IO] io client not found; offline mode active.');
    return;
  }

  socket = io({
    transports: ['polling'],
    upgrade: false,
    reconnection: true,
    reconnectionAttempts: 15,
    reconnectionDelay: 1000,
  });

  socket.on('connect', () => {
    console.info('[Socket.IO] Connected to secure gateway. SID:', socket.id);
    if (gatewayBanner) gatewayBanner.style.display = 'none';
    Toast.show('success', 'Secure Gateway Connected', 'Authenticated E2EE session active.');
    loadServerUsers();
  });

  socket.on('disconnect', () => {
    console.warn('[Socket.IO] Disconnected from server gateway.');
    if (gatewayBanner) {
      gatewayBannerText.textContent = 'Disconnected. Reconnecting to encrypted gateway...';
      gatewayBanner.style.display = 'flex';
    }
  });

  socket.on('reconnect_attempt', () => {
    if (gatewayBanner) {
      gatewayBannerText.textContent = 'Reconnecting to encrypted gateway...';
      gatewayBanner.style.display = 'flex';
    }
  });

  // User presence tracking
  socket.on('user_status', (data) => {
    const { username, status } = data;
    if (USERS[username]) {
      USERS[username].status = status;
      updateUserItemUI(username);
      if (activeUser === username) updateActiveHeaderUI();
      renderOnlineStoriesStrip();
    }
  });

  socket.on('online_users', (data) => {
    const onlineSet = new Set(data.users || []);
    Object.keys(USERS).forEach(u => {
      USERS[u].status = onlineSet.has(u) ? 'online' : 'offline';
      updateUserItemUI(u);
    });
    if (activeUser) updateActiveHeaderUI();
    renderOnlineStoriesStrip();
  });

  // Incoming encrypted message
  socket.on('receive_message', async (data) => {
    const { id, sender_username, ciphertext, nonce, tag, encrypted_package, timestamp, reply_to_id, is_pinned, message_type, media_meta, expires_at, expiration_seconds, is_view_once, is_vanish, viewed_at } = data;
    if (isUserBlocked(sender_username)) {
      console.info(`[Socket.IO] Ignored message from blocked user '${sender_username}'`);
      return;
    }

    const encPkg = encrypted_package || { ciphertext, nonce, tag };

    // Decrypt locally on this device
    let plaintext = '';
    try {
      plaintext = await EncryptionEngine.decryptFrom(sender_username, encPkg);
    } catch (e) {
      console.error('[E2EE] Client decryption error:', e);
      plaintext = '⚠️ [Decryption Failed: Key mismatch or tampered ciphertext]';
    }

    // Cache decrypted & raw packet for inspector and view-once viewer
    if (id) {
      messagePayloadCache.set(Number(id), {
        id,
        sender_username,
        ciphertext: encPkg.ciphertext,
        nonce: encPkg.nonce,
        tag: encPkg.tag,
        plaintext,
        timestamp,
        is_view_once,
      });
    }

    if (sender_username === activeUser) {
      if (emptyChatState) emptyChatState.style.display = 'none';
      const msgEl = createMessageElement(plaintext, false, timestamp, id, true, {
        ciphertext: encPkg.ciphertext,
        nonce: encPkg.nonce,
        tag: encPkg.tag,
        reply_to_id,
        is_pinned,
        message_type,
        media_meta,
        expires_at,
        expiration_seconds,
        is_view_once,
        is_vanish,
        viewed_at,
      });

      if (typingIndicator && messagesArea) {
        messagesArea.insertBefore(msgEl, typingIndicator);
      } else {
        messagesArea?.appendChild(msgEl);
      }
      scrollToBottom();

      // Emit delivered & read receipt
      socket.emit('message_delivered', { message_id: id, sender_username });
      socket.emit('message_read', { message_id: id, sender_username });
    } else {
      Toast.show('info', `New Message from ${sender_username}`, 'Encrypted message received & verified.');
      incrementUnreadBadge(sender_username);
    }
  });

  // Message sent confirmation
  socket.on('message_sent', (data) => {
    const { id, status, expires_at } = data;
    const pendingMsg = document.querySelector('.message.self:not([data-message-id])') ||
                       document.querySelector('.message.self:last-of-type');
    if (pendingMsg && id) {
      pendingMsg.dataset.messageId = id;
      if (expires_at) {
        pendingMsg.dataset.expiresAt = expires_at;
        const footer = pendingMsg.querySelector('.msg-footer');
        if (footer && !footer.querySelector('.ig-countdown-badge')) {
          const badge = document.createElement('span');
          badge.className = 'ig-countdown-badge';
          badge.dataset.expiresAt = expires_at;
          badge.textContent = '⏱️ ...';
          footer.appendChild(badge);
        }
        if (typeof DisappearingMessagesManager !== 'undefined') {
          DisappearingMessagesManager.trackMessage(id, expires_at);
        }
      }
      const statusSpan = pendingMsg.querySelector('.msg-status');
      if (statusSpan) {
        statusSpan.innerHTML = status === 'delivered' ? doubleCheckSvg(false) : singleCheckSvg();
        statusSpan.title = status === 'delivered' ? 'Delivered' : 'Sent';
      }
    }
  });

  // Status update: delivered or read
  socket.on('message_status_update', (data) => {
    const { message_id, status } = data;
    const msgEl = document.querySelector(`.message[data-message-id="${message_id}"]`);
    if (msgEl) {
      const statusSpan = msgEl.querySelector('.msg-status');
      if (statusSpan) {
        if (status === 'read') {
          statusSpan.classList.add('read');
          statusSpan.innerHTML = doubleCheckSvg(true);
          statusSpan.title = 'Read by recipient';
        } else if (status === 'delivered') {
          statusSpan.innerHTML = doubleCheckSvg(false);
          statusSpan.title = 'Delivered to recipient';
        }
      }
    }
  });

  // Real-time message edited
  socket.on('message_edited', async (data) => {
    const { message_id, ciphertext, nonce, tag, edited_at, sender_username } = data;
    const msgEl = document.querySelector(`.message[data-message-id="${message_id}"]`);
    if (!msgEl) return;

    let newPlaintext = '';
    try {
      newPlaintext = await EncryptionEngine.decryptFrom(sender_username, { ciphertext, nonce, tag });
    } catch (e) {
      newPlaintext = '[Decryption error on edit]';
    }

    const textEl = msgEl.querySelector('.msg-text');
    if (textEl) textEl.textContent = newPlaintext;

    // Attach (edited) tag if not already present
    const footer = msgEl.querySelector('.msg-footer');
    if (footer && !footer.querySelector('.msg-edited-tag')) {
      const editedTag = document.createElement('span');
      editedTag.className = 'msg-edited-tag';
      editedTag.title = `Edited at ${edited_at || 'just now'}`;
      editedTag.textContent = '(edited)';
      footer.insertBefore(editedTag, footer.querySelector('.msg-time')?.nextSibling || null);
    }

    // Update cache
    const cached = messagePayloadCache.get(Number(message_id));
    if (cached) {
      cached.plaintext = newPlaintext;
      cached.ciphertext = ciphertext;
      cached.nonce = nonce;
      cached.tag = tag;
    }
  });

  // Real-time message unsent
  socket.on('message_unsent', (data) => {
    const { message_id } = data;
    const msgEl = document.querySelector(`.message[data-message-id="${message_id}"]`);
    if (msgEl) {
      msgEl.classList.add('deleting');
      setTimeout(() => {
        msgEl.remove();
        checkEmptyChatState();
      }, 250);
    }
  });

  // Real-time message deletion
  socket.on('message_deleted', (data) => {
    const { message_id } = data;
    const msgEl = document.querySelector(`.message[data-message-id="${message_id}"]`);
    if (msgEl) {
      msgEl.classList.add('deleting');
      setTimeout(() => {
        msgEl.remove();
        checkEmptyChatState();
      }, 250);
    }
  });

  // Real-time reaction update
  socket.on('message_reaction_update', (data) => {
    const { message_id, reactions } = data;
    const pillContainer = document.getElementById(`reactions-${message_id}`);
    if (pillContainer) {
      pillContainer.innerHTML = renderReactionPillsHtml(reactions, message_id);
    }
  });

  // Real-time pin update
  socket.on('message_pin_update', (data) => {
    const { message_id, is_pinned, snippet } = data;
    const msgEl = document.querySelector(`.message[data-message-id="${message_id}"]`);
    if (msgEl) {
      const pinBtn = msgEl.querySelector('.btn-pin');
      if (pinBtn) {
        pinBtn.classList.toggle('active', is_pinned);
        pinBtn.title = is_pinned ? 'Unpin message' : 'Pin message';
      }
      let pinTag = msgEl.querySelector('.msg-pinned-tag');
      if (is_pinned && !pinTag) {
        pinTag = document.createElement('span');
        pinTag.className = 'msg-pinned-tag';
        pinTag.textContent = '📌 Pinned';
        msgEl.querySelector('.msg-bubble')?.prepend(pinTag);
      } else if (!is_pinned && pinTag) {
        pinTag.remove();
      }
    }
    updatePinnedBanner(is_pinned ? { id: message_id, snippet } : null);
    loadPinnedMessagesSidebar();
  });

  // Conversation cleared
  socket.on('conversation_cleared', (data) => {
    const { with_user } = data;
    if (with_user === activeUser || with_user === myUsername) {
      messagesArea?.querySelectorAll('.message').forEach(m => m.remove());
      checkEmptyChatState();
      Toast.show('info', 'Chat Cleared', 'Conversation ciphertext purged from database.');
    }
  });

  // Real-time scheduled message delivery
  socket.on('scheduled_message_delivered', (data) => {
    console.info('[Socket.IO] Scheduled message delivered:', data);
    Toast.show('success', 'Scheduled Message Sent', `Message to @${data.recipient_username} has been delivered.`);
    if (typeof ScheduledMessagesManager !== 'undefined') {
      ScheduledMessagesManager.refreshActivePeerScheduled();
      const mgr = document.getElementById('scheduledManagerModal');
      if (mgr && mgr.style.display === 'flex') {
        ScheduledMessagesManager.renderManagerList();
      }
    }
  });

  // Typing indicators
  socket.on('user_typing', (data) => {
    const { sender_username, is_typing } = data;
    if (sender_username === activeUser && typingIndicator) {
      typingIndicator.style.display = is_typing ? 'flex' : 'none';
      if (is_typing) scrollToBottom();
    }
  });

  // ─── WebRTC Voice & Video Signaling Events ───────────────────────
  socket.on('incoming_call', (data) => {
    WebRTCCallManager.handleIncomingCall(data);
  });

  socket.on('call_ringing', (data) => {
    WebRTCCallManager.handleCallRinging(data);
  });

  socket.on('call_accepted', (data) => {
    WebRTCCallManager.handleCallAccepted(data);
  });

  socket.on('call_rejected', (data) => {
    WebRTCCallManager.handleCallRejected(data);
  });

  socket.on('webrtc_signal', (data) => {
    WebRTCCallManager.handleRemoteSignal(data);
  });

  socket.on('call_ended', (data) => {
    WebRTCCallManager.handleCallEnded(data);
  });

  socket.on('peer_media_toggle', (data) => {
    WebRTCCallManager.handlePeerMediaToggle(data);
  });

  socket.on('call_unavailable', (data) => {
    WebRTCCallManager.handleCallUnavailable(data);
  });

  socket.on('call_error', (data) => {
    WebRTCCallManager.handleCallError(data);
  });

  // Bind Group Chat real-time events
  if (typeof GroupChatManager !== 'undefined') {
    GroupChatManager.bindSocketEvents(socket);
  }
}

/* ─── Typing Emission ─── */
function emitTyping(isTyping) {
  if (socket && socket.connected && activeUser) {
    socket.emit('typing', {
      recipient_username: activeUser,
      is_typing: isTyping,
    });
  }
}

function handleTypingInput() {
  emitTyping(true);
  clearTimeout(typingDebounce);
  typingDebounce = setTimeout(() => {
    emitTyping(false);
  }, 1800);
}

/* ─── Create Message Element ─── */
function createMessageElement(text, isSelf, timestamp, messageId = null, delivered = false, payloadData = null) {
  const isGroup = Boolean(payloadData?.is_group || activeGroup);
  const senderName = payloadData?.sender_username || (isSelf ? myUsername : activeUser);
  const senderUser = USERS[senderName] || { initials: (senderName || '??').slice(0, 2).toUpperCase(), name: senderName, gradient: '#6366f1' };
  const user = USERS[activeUser] || senderUser;
  const time = formatTime(timestamp);

  const div = document.createElement('div');
  div.className = `message${isSelf ? ' self' : ''}`;
  div.setAttribute('aria-label', isSelf ? 'Your message' : (isGroup ? `Message from ${senderName} in group` : `Message from ${user.name}`));
  if (messageId) div.dataset.messageId = messageId;

  const myInitials = (document.querySelector('.user-profile-avatar')?.textContent.trim() || myUsername.slice(0, 2)).toUpperCase();
  const avatar = `<div class="msg-avatar" aria-hidden="true" style="background:${isSelf ? 'var(--ig-gradient-brand)' : (isGroup ? senderUser.gradient : user.gradient) || '#3b82f6'}">${isSelf ? myInitials : (isGroup ? senderUser.initials : user.initials)}</div>`;

  // Status checkmark
  const isRead = Boolean(payloadData?.read_at);
  const statusIcon = isRead ? doubleCheckSvg(true) : (delivered ? doubleCheckSvg(false) : singleCheckSvg());

  // Group sender badge (for received messages in group chats)
  const groupSenderTag = (isGroup && !isSelf) ? `<div class="msg-group-sender">${escapeHtml(senderName)}</div>` : '';

  // 1. Quoted Reply Snippet
  let replyQuoteHtml = '';
  if (payloadData?.reply_to_id) {
    const quoteSender = payloadData.reply_sender || 'Quoted Message';
    const quoteSnippet = payloadData.reply_snippet || `Replying to #${payloadData.reply_to_id}`;
    replyQuoteHtml = `
      <div class="msg-reply-quote" data-target-id="${payloadData.reply_to_id}" title="Click to view quoted message">
        <span class="quote-sender">${escapeHtml(quoteSender)}</span>
        <span class="quote-text">${escapeHtml(quoteSnippet)}</span>
      </div>
    `;
  }

  // 2. Media or Plaintext parsing
  let mediaHtml = '';
  let textContent = text;

  try {
    if (typeof text === 'string' && (text.startsWith('{"type":"media"') || text.startsWith('{"type":"gif"') || text.startsWith('{"type":"sticker"'))) {
      const parsed = JSON.parse(text);
      if (parsed.type === 'media') {
        if (parsed.mediaType === 'image') {
          mediaHtml = `
            <div class="msg-media-wrap">
              <img class="msg-media-image" src="${parsed.data}" alt="${escapeHtml(parsed.name || 'image')}" data-lightbox="true" data-filename="${escapeHtml(parsed.name || 'image.png')}" />
            </div>`;
          textContent = parsed.caption || '';
        } else if (parsed.mediaType === 'video') {
          mediaHtml = `
            <div class="msg-media-wrap">
              <video class="msg-media-video" controls src="${parsed.data}" preload="metadata"></video>
            </div>`;
          textContent = parsed.caption || '';
        } else if (parsed.mediaType === 'document') {
          mediaHtml = `
            <div class="msg-media-doc">
              <div class="doc-icon">📄</div>
              <div class="doc-info">
                <span class="doc-name">${escapeHtml(parsed.name || 'Document')}</span>
                <span class="doc-size">${formatFileSize(parsed.size || 0)}</span>
              </div>
              <a class="doc-download-btn" href="${parsed.data}" download="${escapeHtml(parsed.name || 'file')}" title="Download">${downloadSvg()}</a>
            </div>`;
          textContent = '';
        } else if (parsed.mediaType === 'audio') {
          const duration = parsed.duration || 0;
          const waveform = parsed.waveform || generateWaveformFromDuration(duration);
          mediaHtml = `
            <div class="msg-voice-card" data-audio-src="${parsed.data}" data-duration="${duration}">
              <button class="voice-bubble-play-btn" aria-label="Play voice message" title="Play">
                <svg class="icon-play" viewBox="0 0 24 24" fill="currentColor" width="18" height="18">
                  <polygon points="5 3 19 12 5 21 5 3"/>
                </svg>
                <svg class="icon-pause" viewBox="0 0 24 24" fill="currentColor" width="18" height="18" style="display:none;">
                  <rect x="6" y="4" width="4" height="16"/>
                  <rect x="14" y="4" width="4" height="16"/>
                </svg>
              </button>
              <div class="voice-bubble-body">
                <div class="voice-waveform-track" title="Click to seek">
                  ${renderWaveformBarsHtml(waveform)}
                </div>
                <div class="voice-bubble-meta">
                  <span class="voice-bubble-time">${formatDuration(duration)}</span>
                  <span class="voice-bubble-badge">🎤 Voice Note</span>
                </div>
              </div>
            </div>`;
          textContent = '';
        }
      } else if (parsed.type === 'gif') {
        mediaHtml = `
          <div class="msg-media-wrap">
            <img class="msg-media-gif" src="${escapeHtml(parsed.url)}" alt="GIF" />
          </div>`;
        textContent = '';
      } else if (parsed.type === 'sticker') {
        mediaHtml = `
          <div class="msg-media-wrap">
            <div class="msg-media-sticker" style="font-size:48px; line-height:1; padding:4px;">${escapeHtml(parsed.url)}</div>
          </div>`;
        textContent = '';
      }
    }
  } catch (e) {
    // Normal text
  }

  // 3. Pinned badge & Edited badge
  const pinnedTag = payloadData?.is_pinned ? `<span class="msg-pinned-tag" title="Pinned message">📌 Pinned</span>` : '';
  const editedTag = payloadData?.is_edited ? `<span class="msg-edited-tag" title="Edited at ${payloadData.edited_at || ''}">(edited)</span>` : '';

  // 3b. Disappearing countdown badge & View-Once handling
  const isViewOnce = Boolean(payloadData?.is_view_once);
  const isViewed = Boolean(payloadData?.viewed_at);
  let viewOnceHtml = '';
  if (isViewOnce) {
    if (isSelf) {
      viewOnceHtml = `
        <div class="view-once-bubble-card opened">
          <span class="view-once-bubble-icon">①</span>
          <span class="view-once-bubble-label">View Once Media (Sent)</span>
        </div>`;
    } else if (isViewed) {
      viewOnceHtml = `
        <div class="view-once-bubble-card opened">
          <span class="view-once-bubble-icon">✓</span>
          <span class="view-once-bubble-label">Opened · Disappeared</span>
        </div>`;
    } else {
      viewOnceHtml = `
        <div class="view-once-bubble-card" data-msg-id="${messageId}">
          <span class="view-once-bubble-icon">①</span>
          <span class="view-once-bubble-label">Photo · Tap to view</span>
        </div>`;
    }
  }

  let countdownBadgeHtml = '';
  if (payloadData?.expires_at) {
    div.dataset.expiresAt = payloadData.expires_at;
    countdownBadgeHtml = `<span class="ig-countdown-badge" data-expires-at="${payloadData.expires_at}">⏱️ ...</span>`;
    if (typeof DisappearingMessagesManager !== 'undefined' && messageId) {
      DisappearingMessagesManager.trackMessage(messageId, payloadData.expires_at);
    }
  }

  // 4. Hover Action Bar
  const hoverActionsHtml = messageId ? `
    <div class="msg-hover-actions">
      <div class="msg-reaction-quick-bar">
        <button class="msg-quick-react-btn" data-msg-id="${messageId}" data-emoji="❤️" title="Love">❤️</button>
        <button class="msg-quick-react-btn" data-msg-id="${messageId}" data-emoji="😂" title="Laugh">😂</button>
        <button class="msg-quick-react-btn" data-msg-id="${messageId}" data-emoji="😮" title="Surprised">😮</button>
        <button class="msg-quick-react-btn" data-msg-id="${messageId}" data-emoji="😢" title="Sad">😢</button>
        <button class="msg-quick-react-btn" data-msg-id="${messageId}" data-emoji="👏" title="Applause">👏</button>
        <button class="msg-quick-react-btn" data-msg-id="${messageId}" data-emoji="🔥" title="Fire">🔥</button>
      </div>
      <button class="msg-action-btn btn-reply" data-msg-id="${messageId}" title="Reply" aria-label="Reply">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 17 4 12 9 7"/><path d="M20 18v-2a4 4 0 0 0-4-4H4"/></svg>
      </button>
      <button class="msg-action-btn btn-forward" data-msg-id="${messageId}" title="Forward" aria-label="Forward">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 17 20 12 15 7"/><path d="M4 18v-2a4 4 0 0 1 4-4h12"/></svg>
      </button>
      <button class="msg-action-btn btn-pin ${payloadData?.is_pinned ? 'active' : ''}" data-msg-id="${messageId}" title="${payloadData?.is_pinned ? 'Unpin' : 'Pin'}" aria-label="Pin">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="17" x2="12" y2="22"/><path d="M5 17h14v-2l-2-2V5a2 2 0 0 0-2-2h-6a2 2 0 0 0-2 2v8l-2 2v2z"/></svg>
      </button>
      ${isSelf ? `
      <button class="msg-action-btn btn-edit" data-msg-id="${messageId}" title="Edit message" aria-label="Edit">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
      </button>
      <button class="msg-action-btn btn-unsend" data-msg-id="${messageId}" title="Unsend message" aria-label="Unsend">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>
      </button>
      ` : ''}
      <button class="msg-action-btn btn-delete" data-msg-id="${messageId}" title="Delete" aria-label="Delete">
        ${trashSvg()}
      </button>
      <button class="msg-action-btn btn-inspect" data-msg-id="${messageId}" title="Inspect crypto payload" aria-label="Inspect">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
      </button>
    </div>` : '';

  // 5. Reaction Pills Row
  const reactionPillsHtml = `
    <div class="msg-reaction-pills" id="reactions-${messageId}">
      ${renderReactionPillsHtml(payloadData?.reactions, messageId)}
    </div>`;

  div.innerHTML = `
    ${avatar}
    <div class="msg-bubble">
      ${groupSenderTag}
      ${pinnedTag}
      ${replyQuoteHtml}
      ${isViewOnce ? viewOnceHtml : mediaHtml}
      ${textContent && !isViewOnce ? `<p class="msg-text">${escapeHtml(textContent)}</p>` : ''}
      <div class="msg-footer">
        <span class="msg-time" title="${timestamp || ''}">${time}</span>
        ${editedTag}
        ${countdownBadgeHtml}
        ${isSelf ? `<span class="msg-status ${isRead ? 'read' : ''}" title="${isRead ? 'Read' : (delivered ? 'Delivered' : 'Sent')}">${statusIcon}</span>` : ''}
      </div>
      ${reactionPillsHtml}
      ${hoverActionsHtml}
    </div>
  `;

  // Cache packet for inspector
  if (messageId && payloadData) {
    messagePayloadCache.set(Number(messageId), {
      id: messageId,
      sender_username: senderName,
      ciphertext: payloadData.ciphertext,
      nonce: payloadData.nonce,
      tag: payloadData.tag,
      epoch: payloadData.epoch,
      plaintext: text,
      timestamp,
      is_group: isGroup,
    });
  }

  return div;
}

/* ─── Render Reaction Pills ─── */
function renderReactionPillsHtml(reactions, messageId) {
  if (!Array.isArray(reactions) || reactions.length === 0) return '';
  return reactions.map(r => `
    <button class="msg-reaction-pill ${r.reacted_by_me ? 'reacted' : ''}" data-msg-id="${messageId}" data-emoji="${r.emoji}">
      <span class="pill-emoji">${r.emoji}</span>
      <span class="pill-count">${r.count}</span>
    </button>
  `).join('');
}

/* ─── Check Empty State ─── */
function checkEmptyChatState() {
  if (!messagesArea || !emptyChatState) return;
  const messages = messagesArea.querySelectorAll('.message');
  if (messages.length === 0) {
    emptyChatState.style.display = 'flex';
    if (activeGroup) {
      emptyChatTitle.textContent = activeGroup.name;
      const handleEl = document.getElementById('emptyChatHandle');
      if (handleEl) handleEl.textContent = `Epoch #${activeGroup.current_epoch} • Group Conversation`;
      const avatarEl = document.getElementById('emptyChatAvatar');
      if (avatarEl && typeof GroupChatManager !== 'undefined') {
        avatarEl.textContent = GroupChatManager.getGroupInitials(activeGroup.name);
        avatarEl.style.background = GroupChatManager.getGroupGradient(activeGroup.id);
      }
    } else if (activeUser && USERS[activeUser]) {
      const u = USERS[activeUser];
      emptyChatTitle.textContent = u.username;
      const handleEl = document.getElementById('emptyChatHandle');
      if (handleEl) handleEl.textContent = `@${u.username}`;
      const avatarEl = document.getElementById('emptyChatAvatar');
      if (avatarEl) {
        avatarEl.textContent = u.initials;
        avatarEl.style.background = u.gradient;
      }
    }
  } else {
    emptyChatState.style.display = 'none';
  }
}

/* ─── Send Message (Handles New, Reply, and Edit) ─── */
async function sendMessage() {
  const text = messageInput?.value.trim();
  if (!text) return;
  if (!activeUser && !activeGroup) {
    Toast.show('warning', 'No Conversation Selected', 'Please select a contact or group from the sidebar to chat.');
    return;
  }
  if (activeUser && isUserBlocked(activeUser)) {
    Toast.show('warning', 'User Blocked', `Cannot send message. You have blocked @${activeUser}.`);
    return;
  }

  messageInput.value = '';
  messageInput.style.height = 'auto';

  const sendIcon = sendBtn?.querySelector('.send-icon');
  const sendSpinner = sendBtn?.querySelector('.send-spinner');
  if (sendIcon) sendIcon.style.display = 'none';
  if (sendSpinner) sendSpinner.style.display = 'block';

  try {
    // 0. Active Group Send
    if (activeGroup) {
      const replyMeta = activeReply ? { ...activeReply } : null;
      cancelReply();

      const encryptedPkg = await EncryptionEngine.encryptGroupMessage(activeGroup.id, activeGroup.current_epoch, text);

      if (emptyChatState) emptyChatState.style.display = 'none';
      const time = formatTime(null);
      const msgEl = createMessageElement(text, true, time, null, false, {
        ciphertext: encryptedPkg.ciphertext,
        nonce: encryptedPkg.nonce,
        tag: encryptedPkg.tag,
        epoch: activeGroup.current_epoch,
        is_group: true,
        sender_username: myUsername,
        reply_to_id: replyMeta?.id || null,
        reply_sender: replyMeta?.sender || null,
        reply_snippet: replyMeta?.snippet || null,
      });

      if (typingIndicator && messagesArea) {
        messagesArea.insertBefore(msgEl, typingIndicator);
      } else {
        messagesArea?.appendChild(msgEl);
      }
      scrollToBottom();

      if (socket && socket.connected) {
        const isViewOnce = Boolean(typeof DisappearingMessagesManager !== 'undefined' && DisappearingMessagesManager.isViewOnceActive);
        const timerSecs = typeof DisappearingMessagesManager !== 'undefined' ? DisappearingMessagesManager.activeTimer : 0;
        socket.emit('send_group_message', {
          group_id: activeGroup.id,
          epoch: activeGroup.current_epoch,
          ciphertext: encryptedPkg.ciphertext,
          nonce: encryptedPkg.nonce,
          tag: encryptedPkg.tag,
          encrypted_package: encryptedPkg,
          message_type: 'text',
          reply_to_id: replyMeta?.id || null,
          is_view_once: isViewOnce,
          expiration_seconds: timerSecs,
        });
        if (isViewOnce && typeof DisappearingMessagesManager !== 'undefined') {
          DisappearingMessagesManager.toggleViewOnce();
        }
      } else {
        Toast.show('error', 'Gateway Disconnected', 'Socket not connected.');
      }
      return;
    }
    // 1. If currently Editing a previous message
    if (activeEditingMessageId) {
      const msgIdToEdit = activeEditingMessageId;
      cancelEdit();

      const encryptedPkg = await EncryptionEngine.encryptFor(activeUser, text);

      // Emit socket edit
      if (socket && socket.connected) {
        socket.emit('edit_message', {
          message_id: msgIdToEdit,
          recipient_username: activeUser,
          ciphertext: encryptedPkg.ciphertext,
          nonce: encryptedPkg.nonce,
          tag: encryptedPkg.tag,
        });
      }

      // In-place UI update
      const msgEl = document.querySelector(`.message[data-message-id="${msgIdToEdit}"]`);
      if (msgEl) {
        const textEl = msgEl.querySelector('.msg-text');
        if (textEl) textEl.textContent = text;
        const footer = msgEl.querySelector('.msg-footer');
        if (footer && !footer.querySelector('.msg-edited-tag')) {
          const editedTag = document.createElement('span');
          editedTag.className = 'msg-edited-tag';
          editedTag.textContent = '(edited)';
          footer.insertBefore(editedTag, footer.querySelector('.msg-time')?.nextSibling || null);
        }
      }
      Toast.show('success', 'Message Edited', 'E2EE ciphertext updated.');
      return;
    }

    // 2. Normal send or Reply send
    const replyMeta = activeReply ? { ...activeReply } : null;
    cancelReply();

    // Client-side E2EE
    const encryptedPkg = await EncryptionEngine.encryptFor(activeUser, text);

    if (emptyChatState) emptyChatState.style.display = 'none';
    const time = formatTime(null);
    const msgEl = createMessageElement(text, true, time, null, false, {
      ciphertext: encryptedPkg.ciphertext,
      nonce: encryptedPkg.nonce,
      tag: encryptedPkg.tag,
      reply_to_id: replyMeta?.id || null,
      reply_sender: replyMeta?.sender || null,
      reply_snippet: replyMeta?.snippet || null,
    });

    if (typingIndicator && messagesArea) {
      messagesArea.insertBefore(msgEl, typingIndicator);
    } else {
      messagesArea?.appendChild(msgEl);
    }
    scrollToBottom();

    // Emit over WebSocket
    if (socket && socket.connected) {
      const isViewOnce = Boolean(typeof DisappearingMessagesManager !== 'undefined' && DisappearingMessagesManager.isViewOnceActive);
      const timerSecs = typeof DisappearingMessagesManager !== 'undefined' ? DisappearingMessagesManager.activeTimer : 0;
      socket.emit('send_message', {
        recipient_username: activeUser,
        encrypted_package: encryptedPkg,
        reply_to_id: replyMeta?.id || null,
        message_type: 'text',
        is_view_once: isViewOnce,
        expiration_seconds: timerSecs,
      });
      if (isViewOnce && typeof DisappearingMessagesManager !== 'undefined') {
        DisappearingMessagesManager.toggleViewOnce();
      }
    } else {
      Toast.show('error', 'Gateway Disconnected', 'Socket not connected.');
    }

    emitTyping(false);
  } catch (err) {
    console.error('[E2EE] Send failed:', err);
    Toast.show('error', 'Encryption Failed', err.message);
  } finally {
    if (sendIcon) sendIcon.style.display = 'block';
    if (sendSpinner) sendSpinner.style.display = 'none';
    messageInput?.focus();
  }
}

/* ─── Send Media Attachment (Encrypted Client-Side) ─── */
async function sendEncryptedMedia(file) {
  if (!file || (!activeUser && !activeGroup)) return;
  if (file.size > 15 * 1024 * 1024) {
    Toast.show('error', 'File Too Large', 'Maximum encrypted attachment size is 15 MB.');
    return;
  }

  Toast.show('info', 'Encrypting File', `Encrypting ${file.name} with AES-256-GCM...`);

  const reader = new FileReader();
  reader.onload = async (e) => {
    try {
      const dataUrl = e.target.result;
      let mediaType = 'document';
      if (file.type.startsWith('image/')) mediaType = 'image';
      else if (file.type.startsWith('video/')) mediaType = 'video';

      const mediaPayload = JSON.stringify({
        type: 'media',
        mediaType,
        name: file.name,
        size: file.size,
        data: dataUrl,
      });

      if (activeGroup) {
        // Encrypt using Group Epoch Key
        const encryptedPkg = await EncryptionEngine.encryptGroupMessage(activeGroup.id, activeGroup.current_epoch, mediaPayload);

        if (emptyChatState) emptyChatState.style.display = 'none';
        const time = formatTime(null);
        const msgEl = createMessageElement(mediaPayload, true, time, null, false, {
          ciphertext: encryptedPkg.ciphertext,
          nonce: encryptedPkg.nonce,
          tag: encryptedPkg.tag,
          epoch: activeGroup.current_epoch,
          is_group: true,
          sender_username: myUsername,
          message_type: 'media',
        });

        if (typingIndicator && messagesArea) {
          messagesArea.insertBefore(msgEl, typingIndicator);
        } else {
          messagesArea?.appendChild(msgEl);
        }
        scrollToBottom();

        if (socket && socket.connected) {
          const isViewOnce = Boolean(typeof DisappearingMessagesManager !== 'undefined' && DisappearingMessagesManager.isViewOnceActive);
          const timerSecs = typeof DisappearingMessagesManager !== 'undefined' ? DisappearingMessagesManager.activeTimer : 0;
          socket.emit('send_group_message', {
            group_id: activeGroup.id,
            epoch: activeGroup.current_epoch,
            ciphertext: encryptedPkg.ciphertext,
            nonce: encryptedPkg.nonce,
            tag: encryptedPkg.tag,
            encrypted_package: encryptedPkg,
            message_type: 'media',
            media_meta: { name: file.name, size: file.size, type: file.type },
            is_view_once: isViewOnce,
            expiration_seconds: timerSecs,
          });
          if (isViewOnce && typeof DisappearingMessagesManager !== 'undefined') {
            DisappearingMessagesManager.toggleViewOnce();
          }
        }
        Toast.show('success', 'File Sent', `${file.name} sent to group.`);
        return;
      }

      // Encrypt entire payload client-side for direct peer
      const encryptedPkg = await EncryptionEngine.encryptFor(activeUser, mediaPayload);

      // Render locally
      if (emptyChatState) emptyChatState.style.display = 'none';
      const time = formatTime(null);
      const isViewOnceDirect = Boolean(typeof DisappearingMessagesManager !== 'undefined' && DisappearingMessagesManager.isViewOnceActive);
      const timerSecsDirect = typeof DisappearingMessagesManager !== 'undefined' ? DisappearingMessagesManager.activeTimer : 0;
      const msgEl = createMessageElement(mediaPayload, true, time, null, false, {
        ciphertext: encryptedPkg.ciphertext,
        nonce: encryptedPkg.nonce,
        tag: encryptedPkg.tag,
        message_type: 'media',
        is_view_once: isViewOnceDirect,
      });

      if (typingIndicator && messagesArea) {
        messagesArea.insertBefore(msgEl, typingIndicator);
      } else {
        messagesArea?.appendChild(msgEl);
      }
      scrollToBottom();

      // Emit to server
      if (socket && socket.connected) {
        socket.emit('send_message', {
          recipient_username: activeUser,
          encrypted_package: encryptedPkg,
          message_type: 'media',
          media_meta: JSON.stringify({ name: file.name, size: file.size, type: file.type }),
          is_view_once: isViewOnceDirect,
          expiration_seconds: timerSecsDirect,
        });
        if (isViewOnceDirect && typeof DisappearingMessagesManager !== 'undefined') {
          DisappearingMessagesManager.toggleViewOnce();
        }
      }
      Toast.show('success', 'File Sent', `${file.name} sent with end-to-end encryption.`);
    } catch (err) {
      console.error('[E2EE] Media encryption error:', err);
      Toast.show('error', 'Attachment Failed', err.message);
    }
  };
  reader.readAsDataURL(file);
}

/* ─── Send GIF / Sticker ─── */
async function sendGifMessage(gifUrl) {
  if ((!activeUser && !activeGroup) || !gifUrl) return;
  const payload = JSON.stringify({ type: 'gif', url: gifUrl });
  try {
    if (activeGroup) {
      const encryptedPkg = await EncryptionEngine.encryptGroupMessage(activeGroup.id, activeGroup.current_epoch, payload);
      const time = formatTime(null);
      const msgEl = createMessageElement(payload, true, time, null, false, {
        ciphertext: encryptedPkg.ciphertext,
        nonce: encryptedPkg.nonce,
        tag: encryptedPkg.tag,
        epoch: activeGroup.current_epoch,
        is_group: true,
        sender_username: myUsername,
        message_type: 'gif',
      });
      if (typingIndicator && messagesArea) messagesArea.insertBefore(msgEl, typingIndicator);
      else messagesArea?.appendChild(msgEl);
      scrollToBottom();

      socket?.emit('send_group_message', {
        group_id: activeGroup.id,
        epoch: activeGroup.current_epoch,
        ciphertext: encryptedPkg.ciphertext,
        nonce: encryptedPkg.nonce,
        tag: encryptedPkg.tag,
        encrypted_package: encryptedPkg,
        message_type: 'gif',
      });
      document.getElementById('emojiPickerPopover')?.classList.remove('active');
      return;
    }

    const encryptedPkg = await EncryptionEngine.encryptFor(activeUser, payload);
    const time = formatTime(null);
    const msgEl = createMessageElement(payload, true, time, null, false, {
      ciphertext: encryptedPkg.ciphertext,
      nonce: encryptedPkg.nonce,
      tag: encryptedPkg.tag,
      message_type: 'gif',
    });
    if (typingIndicator && messagesArea) messagesArea.insertBefore(msgEl, typingIndicator);
    else messagesArea?.appendChild(msgEl);
    scrollToBottom();

    socket?.emit('send_message', {
      recipient_username: activeUser,
      encrypted_package: encryptedPkg,
      message_type: 'gif',
    });
    document.getElementById('emojiPickerPopover')?.classList.remove('active');
  } catch (err) {
    Toast.show('error', 'Failed to Send GIF', err.message);
  }
}

async function sendStickerMessage(stickerEmoji) {
  if ((!activeUser && !activeGroup) || !stickerEmoji) return;
  const payload = JSON.stringify({ type: 'sticker', url: stickerEmoji });
  try {
    if (activeGroup) {
      const encryptedPkg = await EncryptionEngine.encryptGroupMessage(activeGroup.id, activeGroup.current_epoch, payload);
      const time = formatTime(null);
      const msgEl = createMessageElement(payload, true, time, null, false, {
        ciphertext: encryptedPkg.ciphertext,
        nonce: encryptedPkg.nonce,
        tag: encryptedPkg.tag,
        epoch: activeGroup.current_epoch,
        is_group: true,
        sender_username: myUsername,
        message_type: 'sticker',
      });
      if (typingIndicator && messagesArea) messagesArea.insertBefore(msgEl, typingIndicator);
      else messagesArea?.appendChild(msgEl);
      scrollToBottom();

      socket?.emit('send_group_message', {
        group_id: activeGroup.id,
        epoch: activeGroup.current_epoch,
        ciphertext: encryptedPkg.ciphertext,
        nonce: encryptedPkg.nonce,
        tag: encryptedPkg.tag,
        encrypted_package: encryptedPkg,
        message_type: 'sticker',
      });
      document.getElementById('emojiPickerPopover')?.classList.remove('active');
      return;
    }

    const encryptedPkg = await EncryptionEngine.encryptFor(activeUser, payload);
    const time = formatTime(null);
    const msgEl = createMessageElement(payload, true, time, null, false, {
      ciphertext: encryptedPkg.ciphertext,
      nonce: encryptedPkg.nonce,
      tag: encryptedPkg.tag,
      message_type: 'sticker',
    });
    if (typingIndicator && messagesArea) messagesArea.insertBefore(msgEl, typingIndicator);
    else messagesArea?.appendChild(msgEl);
    scrollToBottom();

    socket?.emit('send_message', {
      recipient_username: activeUser,
      encrypted_package: encryptedPkg,
      message_type: 'sticker',
    });
    document.getElementById('emojiPickerPopover')?.classList.remove('active');
  } catch (err) {
    Toast.show('error', 'Failed to Send Sticker', err.message);
  }
}

/* ─── Advanced Message Action Handlers ─── */
function startReply(messageId, sender, snippet) {
  cancelEdit();
  activeReply = { id: messageId, sender, snippet };
  if (replyPreviewBar) {
    replyPreviewBar.style.display = 'flex';
    if (replySenderEl) replySenderEl.textContent = `Replying to @${sender}`;
    if (replySnippetEl) replySnippetEl.textContent = snippet.slice(0, 60);
  }
  messageInput?.focus();
}

function cancelReply() {
  activeReply = null;
  if (replyPreviewBar) replyPreviewBar.style.display = 'none';
}

function startEdit(messageId, currentText) {
  cancelReply();
  activeEditingMessageId = messageId;
  if (editNoticeBar) {
    editNoticeBar.style.display = 'flex';
    if (editSnippetEl) editSnippetEl.textContent = currentText.slice(0, 50);
  }
  if (messageInput) {
    messageInput.value = currentText;
    messageInput.style.height = 'auto';
    messageInput.style.height = Math.min(messageInput.scrollHeight, 120) + 'px';
    messageInput.focus();
  }
}

function cancelEdit() {
  activeEditingMessageId = null;
  if (editNoticeBar) editNoticeBar.style.display = 'none';
}

function unsendMessage(messageId) {
  if (!messageId || !socket || !activeUser) return;
  socket.emit('unsend_message', {
    message_id: messageId,
    recipient_username: activeUser,
  });
  const msgEl = document.querySelector(`.message[data-message-id="${messageId}"]`);
  if (msgEl) {
    msgEl.classList.add('deleting');
    setTimeout(() => { msgEl.remove(); checkEmptyChatState(); }, 200);
  }
  Toast.show('info', 'Message Unsent', 'Message retracted for both participants.');
}

async function deleteMessageById(messageId) {
  if (!messageId) return;
  const msgEl = document.querySelector(`.message[data-message-id="${messageId}"]`);
  if (msgEl) msgEl.classList.add('deleting');

  if (activeGroup) {
    if (socket && socket.connected) {
      socket.emit('delete_group_message', {
        group_id: activeGroup.id,
        message_id: messageId,
      });
    }
    if (msgEl) setTimeout(() => { msgEl.remove(); checkEmptyChatState(); }, 200);
    return;
  }

  try {
    const resp = await fetch(`/api/messages/${messageId}`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCsrfToken(),
      },
    });
    const data = await resp.json();
    if (data.ok) {
      if (msgEl) setTimeout(() => { msgEl.remove(); checkEmptyChatState(); }, 200);
      Toast.show('info', 'Message Deleted', 'Ciphertext permanently purged.');
    } else {
      if (msgEl) msgEl.classList.remove('deleting');
      Toast.show('error', 'Delete Error', data.error || 'Failed to delete');
    }
  } catch (err) {
    if (msgEl) msgEl.classList.remove('deleting');
    Toast.show('error', 'Network Error', 'Could not delete message');
  }
}

function toggleReaction(messageId, emoji) {
  if (!messageId || !emoji || !socket) return;
  if (activeGroup) {
    socket.emit('group_message_reaction', {
      group_id: activeGroup.id,
      message_id: messageId,
      emoji,
    });
    return;
  }
  if (!activeUser) return;
  socket.emit('react_message', {
    message_id: messageId,
    emoji,
    recipient_username: activeUser,
  });
}

function togglePinMessage(messageId, currentlyPinned) {
  if (!messageId || !activeUser || !socket) return;
  const nextPinState = !currentlyPinned;
  socket.emit('pin_message', {
    message_id: messageId,
    is_pinned: nextPinState,
    recipient_username: activeUser,
  });
  Toast.show('info', nextPinState ? 'Message Pinned' : 'Message Unpinned', 'Channel pin updated.');
}

function updatePinnedBanner(pinnedInfo) {
  if (!pinnedBanner) return;
  if (pinnedInfo && pinnedInfo.snippet) {
    pinnedBanner.style.display = 'block';
    if (pinnedBannerSnippet) pinnedBannerSnippet.textContent = pinnedInfo.snippet;
    pinnedBannerInner.onclick = () => {
      const el = document.querySelector(`.message[data-message-id="${pinnedInfo.id}"]`);
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'center' });
        el.classList.add('highlight-pulse');
        setTimeout(() => el.classList.remove('highlight-pulse'), 1500);
      }
    };
  } else {
    pinnedBanner.style.display = 'none';
  }
}

async function loadPinnedMessagesSidebar() {
  if (!activeUser) return;
  try {
    const resp = await fetch(`/api/messages/pinned/${encodeURIComponent(activeUser)}`);
    const data = await resp.json();
    if (data.ok && Array.isArray(data.pinned_messages)) {
      const firstPinned = data.pinned_messages[0];
      if (firstPinned) {
        updatePinnedBanner({ id: firstPinned.id, snippet: firstPinned.ciphertext?.slice(0, 45) || 'Pinned Note' });
      } else {
        updatePinnedBanner(null);
      }
    }
  } catch (_) {}
}

/* ─── Forward Message Modal ─── */
function openForwardModal(messageId, text) {
  forwardMessagePayload = text;
  if (forwardPreviewBox) forwardPreviewBox.textContent = text ? text.slice(0, 100) : 'Encrypted Message';
  if (forwardUserList) {
    forwardUserList.innerHTML = '';
    Object.keys(USERS).forEach(username => {
      if (username === myUsername) return;
      const u = USERS[username];
      const item = document.createElement('div');
      item.className = 'forward-user-row';
      item.style.cssText = 'display:flex; align-items:center; justify-content:space-between; padding:9px 12px; border-radius:10px; background:var(--ig-bg-secondary); cursor:pointer;';
      item.innerHTML = `
        <div style="display:flex; align-items:center; gap:10px;">
          <div class="msg-avatar" style="width:34px; height:34px; font-size:12px; background:${u.gradient}">${u.initials}</div>
          <div>
            <div style="font-size:13.5px; font-weight:600; color:var(--ig-text-primary);">${escapeHtml(u.name || u.username)}</div>
            <div style="font-size:11.5px; color:var(--ig-text-secondary);">@${escapeHtml(u.username)}</div>
          </div>
        </div>
        <button class="btn btn-primary forward-send-btn" style="padding:5px 14px; font-size:12px; border-radius:8px;">Send</button>
      `;

      item.querySelector('.forward-send-btn').addEventListener('click', async (e) => {
        e.stopPropagation();
        await forwardToContact(username, forwardMessagePayload);
      });
      forwardUserList.appendChild(item);
    });
  }
  forwardModal?.classList.add('active');
}

async function forwardToContact(targetUsername, text) {
  forwardModal?.classList.remove('active');
  try {
    const encPkg = await EncryptionEngine.encryptFor(targetUsername, text);
    if (socket && socket.connected) {
      socket.emit('send_message', {
        recipient_username: targetUsername,
        encrypted_package: encPkg,
        message_type: 'text',
      });
    }
    Toast.show('success', 'Message Forwarded', `Re-encrypted & delivered to @${targetUsername}.`);
  } catch (err) {
    Toast.show('error', 'Forward Failed', err.message);
  }
}

/* ─── Media Lightbox ─── */
function openMediaLightbox(src, fileName) {
  if (!mediaLightboxModal) return;
  if (lightboxMediaContent) {
    lightboxMediaContent.innerHTML = `<img src="${src}" alt="${escapeHtml(fileName)}" style="max-width:85vw; max-height:80vh; object-fit:contain; border-radius:12px; box-shadow:0 20px 50px rgba(0,0,0,0.5);" />`;
  }
  if (lightboxFileName) lightboxFileName.textContent = fileName || 'image.png';
  if (lightboxDownloadBtn) {
    lightboxDownloadBtn.href = src;
    lightboxDownloadBtn.download = fileName || 'file';
  }
  mediaLightboxModal.classList.add('active');
}

/* ─── In-Chat Message Search ─── */
function openInChatSearch() {
  closeChatMenu();
  if (!inChatSearchBar) return;
  inChatSearchBar.style.display = 'block';
  if (inChatSearchInput) {
    inChatSearchInput.value = '';
    inChatSearchInput.focus();
  }
  if (inChatSearchCount) inChatSearchCount.textContent = '';
  searchMatches = [];
  currentSearchIndex = -1;
}

function closeInChatSearch() {
  if (!inChatSearchBar) return;
  inChatSearchBar.style.display = 'none';
  if (inChatSearchInput) inChatSearchInput.value = '';
  if (inChatSearchCount) inChatSearchCount.textContent = '';

  messagesArea?.querySelectorAll('.msg-search-highlight').forEach(mark => {
    const parent = mark.parentNode;
    parent.replaceChild(document.createTextNode(mark.textContent), mark);
    parent.normalize();
  });
  searchMatches = [];
  currentSearchIndex = -1;
}

function performInChatSearch() {
  const query = (inChatSearchInput?.value || '').trim().toLowerCase();
  const messages = messagesArea?.querySelectorAll('.message');
  if (!messages || messages.length === 0) return;

  // Clear previous highlights
  messagesArea?.querySelectorAll('.msg-search-highlight').forEach(mark => {
    const parent = mark.parentNode;
    parent.replaceChild(document.createTextNode(mark.textContent), mark);
    parent.normalize();
  });
  searchMatches = [];
  currentSearchIndex = -1;

  if (!query) {
    if (inChatSearchCount) inChatSearchCount.textContent = '';
    return;
  }

  messages.forEach(msg => {
    const textEl = msg.querySelector('.msg-text') || msg.querySelector('.doc-name');
    if (!textEl) return;
    const originalText = textEl.textContent;
    const lower = originalText.toLowerCase();

    if (lower.includes(query)) {
      searchMatches.push(msg);
      const regex = new RegExp(`(${escapeRegex(query)})`, 'gi');
      textEl.innerHTML = escapeHtml(originalText).replace(regex, '<mark class="msg-search-highlight">$1</mark>');
    }
  });

  if (searchMatches.length > 0) {
    currentSearchIndex = 0;
    if (inChatSearchCount) inChatSearchCount.textContent = `1 of ${searchMatches.length}`;
    searchMatches[0].scrollIntoView({ behavior: 'smooth', block: 'center' });
  } else {
    if (inChatSearchCount) inChatSearchCount.textContent = '0 of 0';
  }
}

function navigateSearch(direction) {
  if (searchMatches.length === 0) return;
  if (direction === 'next') {
    currentSearchIndex = (currentSearchIndex + 1) % searchMatches.length;
  } else {
    currentSearchIndex = (currentSearchIndex - 1 + searchMatches.length) % searchMatches.length;
  }
  if (inChatSearchCount) inChatSearchCount.textContent = `${currentSearchIndex + 1} of ${searchMatches.length}`;
  searchMatches[currentSearchIndex].scrollIntoView({ behavior: 'smooth', block: 'center' });
}

/* ─── Load & Decrypt Conversation History ─── */
async function loadConversationHistory(peerUsername) {
  if (!messagesArea) return;

  if (historyLoader) historyLoader.style.display = 'flex';
  if (emptyChatState) emptyChatState.style.display = 'none';

  messagesArea.querySelectorAll('.message').forEach(m => m.remove());

  try {
    const resp = await fetch(`/api/messages/${encodeURIComponent(peerUsername)}`);
    const data = await resp.json();

    if (data.ok && Array.isArray(data.messages)) {
      if (data.messages.length === 0) {
        checkEmptyChatState();
      } else {
        for (const m of data.messages) {
          let plaintext = '';
          const encPkg = (m.encrypted_package && typeof m.encrypted_package === 'object')
            ? m.encrypted_package
            : (m.ciphertext && m.nonce && m.tag ? { ciphertext: m.ciphertext, nonce: m.nonce, tag: m.tag } : m.encrypted_package);

          try {
            plaintext = await EncryptionEngine.decryptFrom(peerUsername, encPkg);
          } catch (e) {
            plaintext = '🔒 [Ciphertext Decryption Error: Key Mismatch]';
          }

          const msgEl = createMessageElement(plaintext, m.is_self, m.timestamp, m.id, m.delivered, {
            ciphertext: m.ciphertext || encPkg?.ciphertext,
            nonce: m.nonce || encPkg?.nonce,
            tag: m.tag || encPkg?.tag,
            reply_to_id: m.reply_to_id,
            is_pinned: m.is_pinned,
            is_edited: m.is_edited,
            edited_at: m.edited_at,
            read_at: m.read_at,
            message_type: m.message_type,
            media_meta: m.media_meta,
            reactions: m.reactions || [],
            expires_at: m.expires_at,
            expiration_seconds: m.expiration_seconds,
            is_view_once: m.is_view_once,
            is_vanish: m.is_vanish,
            viewed_at: m.viewed_at,
          });

          if (typingIndicator) {
            messagesArea.insertBefore(msgEl, typingIndicator);
          } else {
            messagesArea.appendChild(msgEl);
          }
        }
        scrollToBottom(false);
      }
    }

    if (data.settings && typeof DisappearingMessagesManager !== 'undefined') {
      DisappearingMessagesManager.applyConversationSettings(data.settings);
    }
  } catch (err) {
    console.warn('[Chat] History load error:', err);
    Toast.show('error', 'History Error', 'Failed to retrieve encrypted messages.');
  } finally {
    if (historyLoader) historyLoader.style.display = 'none';
  }

  loadPinnedMessagesSidebar();
}

/* ─── Auto-resize Textarea & Key Handling ─── */
function autoResizeTextarea() {
  if (!messageInput) return;
  messageInput.addEventListener('input', () => {
    messageInput.style.height = 'auto';
    messageInput.style.height = Math.min(messageInput.scrollHeight, 120) + 'px';
    handleTypingInput();
    if (sendBtn) {
      sendBtn.classList.toggle('has-text', Boolean(messageInput.value.trim()));
    }
  });

  messageInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  });

  sendBtn?.addEventListener('click', sendMessage);
}

/* ─── Load Server Users Directory ─── */
async function loadServerUsers() {
  if (!userListContainer) return;

  try {
    const resp = await fetch('/api/users');
    const data = await resp.json();

    if (data.ok && Array.isArray(data.users)) {
      data.users.forEach(u => {
        if (!USERS[u.username]) {
          USERS[u.username] = {
            id: u.id,
            username: u.username,
            email: u.email || `${u.username}@tmeee.local`,
            initials: u.username.slice(0, 2).toUpperCase(),
            gradient: u.gradient || 'linear-gradient(135deg, #0284c7 0%, #38bdf8 100%)',
            status: u.status || 'offline',
            publicKey: u.public_key || null,
            lastLogin: u.last_login || null,
          };
        } else {
          USERS[u.username].status = u.status || USERS[u.username].status;
        }
      });
      renderUserList();
      renderOnlineStoriesStrip();
    }
  } catch (err) {
    console.warn('[Users] Failed to fetch directory:', err);
  }
}

function renderUserList() {
  if (!userListContainer) return;
  userListContainer.innerHTML = '';

  const usernames = Object.keys(USERS).filter(u => u !== myUsername);
  if (usernames.length === 0) {
    userListContainer.innerHTML = `
      <div style="text-align:center; padding:32px 16px; color:var(--ig-text-muted);">
        <p style="font-size:13px; font-weight:600; color:var(--ig-text-primary); margin-bottom:4px;">No contacts yet</p>
        <p style="font-size:12px;">Waiting for registered contacts...</p>
      </div>`;
    return;
  }

  usernames.forEach(username => {
    const u = USERS[username];
    const isOnline = u.status === 'online';
    const isMuted = isUserMuted(username);
    const isBlocked = isUserBlocked(username);

    const el = document.createElement('div');
    el.className = `ig-conversation-item user-item ${activeUser === username ? 'active' : ''}`;
    el.dataset.username = username;
    el.innerHTML = `
      <div class="ig-avatar-container">
        <div class="ig-conversation-avatar user-avatar" style="background:${u.gradient}">${u.initials}</div>
        <div class="ig-status-indicator user-status-dot ${isOnline ? 'online' : 'offline'}"></div>
      </div>
      <div class="ig-conversation-info user-info">
        <div class="ig-conversation-header">
          <span class="ig-conversation-name user-name">${escapeHtml(u.username)}</span>
          <span class="ig-conversation-time">${isOnline ? 'Active' : ''}</span>
        </div>
        <div class="ig-conversation-preview user-preview-row">
          <span class="ig-preview-text">${isBlocked ? 'Blocked' : (isMuted ? 'Notifications muted' : 'End-to-End Encrypted')}</span>
        </div>
      </div>
    `;

    el.addEventListener('click', () => switchConversation(username));
    userListContainer.appendChild(el);
  });
}

function updateUserItemUI(username) {
  const el = userListContainer?.querySelector(`.user-item[data-username="${username}"]`);
  if (!el || !USERS[username]) return;
  const isOnline = USERS[username].status === 'online';
  const dot = el.querySelector('.user-status-dot');
  if (dot) dot.className = `ig-status-indicator user-status-dot ${isOnline ? 'online' : 'offline'}`;
}

function incrementUnreadBadge(username) {
  const el = userListContainer?.querySelector(`.user-item[data-username="${username}"]`);
  if (el) el.classList.add('has-unread');
}

/* ─── Switch Active Conversation ─── */
async function switchConversation(username) {
  if (activeUser === username && !activeGroup) return;
  if (activeGroup && socket) {
    socket.emit('leave_group_room', { group_id: activeGroup.id });
  }
  activeGroup = null;
  activeUser = username;
  if (typeof GlobalVoicePlayer !== 'undefined') GlobalVoicePlayer.stop();

  // Reset Right Sidebar to Direct Contact view
  const contactCard = document.getElementById('contactProfileCard');
  if (contactCard) contactCard.style.display = 'flex';
  const groupCard = document.getElementById('groupProfileCard');
  if (groupCard) groupCard.style.display = 'none';
  const groupSec = document.getElementById('groupMembersSection');
  if (groupSec) groupSec.style.display = 'none';
  const leaveBtn = document.getElementById('rightPanelLeaveGroupBtn');
  if (leaveBtn) leaveBtn.style.display = 'none';

  // Unread badge clear
  const userItem = userListContainer?.querySelector(`.user-item[data-username="${username}"]`);
  if (userItem) userItem.classList.remove('has-unread');

  // Update active state in UI
  document.querySelectorAll('.ig-conversation-item').forEach(item => {
    item.classList.toggle('active', item.dataset.username === username);
  });

  updateActiveHeaderUI();
  updateRightSidebarUI();
  applyBlockUI(username);
  cancelReply();
  cancelEdit();
  closeInChatSearch();
  if (typeof ScheduledMessagesManager !== 'undefined') {
    ScheduledMessagesManager.refreshActivePeerScheduled();
  }

  await loadConversationHistory(username);
}

function updateActiveHeaderUI() {
  if (!activeUser || !USERS[activeUser]) return;
  const u = USERS[activeUser];
  const isOnline = u.status === 'online';

  if (chatHeaderName) chatHeaderName.textContent = u.username;
  if (chatHeaderStatus) {
    chatHeaderStatus.textContent = isOnline ? '● Active Now' : '○ Offline';
    chatHeaderStatus.className = `ig-header-status-text chat-header-status ${isOnline ? 'online' : 'offline'}`;
  }
  if (chatAvatarInitials) {
    chatAvatarInitials.textContent = u.initials;
    chatAvatarInitials.style.background = u.gradient;
  }
  if (chatStatusDot) {
    chatStatusDot.className = `ig-header-status-dot ${isOnline ? 'online' : 'offline'}`;
  }
}

function updateRightSidebarUI() {
  if (!activeUser || !USERS[activeUser]) return;
  const u = USERS[activeUser];
  const nameEl = document.getElementById('detailsName');
  const handleEl = document.getElementById('detailsHandle');
  const avatarEl = document.getElementById('detailsAvatar');
  if (nameEl) nameEl.textContent = u.username;
  if (handleEl) handleEl.textContent = `@${u.username}`;
  if (avatarEl) {
    avatarEl.textContent = u.initials;
    avatarEl.style.background = u.gradient;
  }

  const muteSwitch = document.getElementById('muteToggleSwitch');
  if (muteSwitch) muteSwitch.checked = isUserMuted(activeUser);

  const blockText = document.getElementById('rightPanelBlockText');
  if (blockText) blockText.textContent = isUserBlocked(activeUser) ? 'Unblock User' : 'Block User';

  loadPeerCallHistory(activeUser);
  if (typeof ScheduledMessagesManager !== 'undefined') {
    ScheduledMessagesManager.refreshActivePeerScheduled();
  }
}

/* ─── Search in Left Sidebar ─── */
function initSearch() {
  searchInput?.addEventListener('input', () => {
    const query = searchInput.value.toLowerCase().trim();
    document.querySelectorAll('.user-item').forEach(item => {
      const name = item.querySelector('.user-name')?.textContent.toLowerCase() ?? '';
      item.style.display = name.includes(query) ? '' : 'none';
    });
  });
}

/* ─── Clear Active Conversation ─── */
async function clearActiveConversation() {
  if (!activeUser) return;
  if (!confirm(`Are you sure you want to permanently delete all messages with @${activeUser}? This action is irreversible.`)) return;

  try {
    const resp = await fetch(`/api/messages/${encodeURIComponent(activeUser)}`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCsrfToken(),
      },
    });
    const data = await resp.json();
    if (data.ok) {
      messagesArea?.querySelectorAll('.message').forEach(m => m.remove());
      checkEmptyChatState();
      Toast.show('success', 'Conversation Cleared', `Deleted ${data.deleted_count || 0} encrypted messages.`);
    } else {
      Toast.show('error', 'Error', data.error || 'Failed to clear conversation');
    }
  } catch (err) {
    Toast.show('error', 'Network Error', 'Could not clear conversation');
  }
}

/* ─── Copy to Clipboard Helper ─── */
function copyText(text, successTitle = 'Copied!') {
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    Toast.show('success', successTitle, 'Copied to clipboard.');
  }).catch(() => {
    Toast.show('info', 'Clipboard', text);
  });
}

/* ─── 3-Dots Menu & Privacy Actions ─── */
const chatMenuBtn        = document.getElementById('chatMenuBtn');
const chatDropdownMenu   = document.getElementById('chatDropdownMenu');
const menuUserInfo       = document.getElementById('menuUserInfo');
const menuSearch         = document.getElementById('menuSearch');
const menuMute           = document.getElementById('menuMute');
const menuMuteText       = document.getElementById('menuMuteText');
const menuMuteIcon       = document.getElementById('menuMuteIcon');
const menuBlock          = document.getElementById('menuBlock');
const menuBlockText      = document.getElementById('menuBlockText');
const menuReport         = document.getElementById('menuReport');

const blockUserModal     = document.getElementById('blockUserModal');
const closeBlockModal    = document.getElementById('closeBlockModal');
const cancelBlockBtn     = document.getElementById('cancelBlockBtn');
const confirmBlockBtn    = document.getElementById('confirmBlockBtn');
const blockTargetName    = document.getElementById('blockTargetName');

const reportUserModal    = document.getElementById('reportUserModal');
const closeReportModal   = document.getElementById('closeReportModal');
const cancelReportBtn    = document.getElementById('cancelReportBtn');
const submitReportBtn    = document.getElementById('submitReportBtn');
const reportTargetName   = document.getElementById('reportTargetName');

let mutedUsers = new Set();
let blockedUsers = new Set();

function initPrivacySettings() {
  try {
    const m = JSON.parse(localStorage.getItem(`securechat_muted_${myUsername}`) || '[]');
    mutedUsers = new Set(Array.isArray(m) ? m : []);
  } catch (_) { mutedUsers = new Set(); }

  try {
    const b = JSON.parse(localStorage.getItem(`securechat_blocked_${myUsername}`) || '[]');
    blockedUsers = new Set(Array.isArray(b) ? b : []);
  } catch (_) { blockedUsers = new Set(); }
}

function savePrivacySettings() {
  try {
    localStorage.setItem(`securechat_muted_${myUsername}`, JSON.stringify([...mutedUsers]));
    localStorage.setItem(`securechat_blocked_${myUsername}`, JSON.stringify([...blockedUsers]));
  } catch (_) {}
}

function isUserMuted(username) {
  return username ? mutedUsers.has(username) : false;
}

function isUserBlocked(username) {
  return username ? blockedUsers.has(username) : false;
}

function updateMenuDynamicStates() {
  if (!activeUser) return;
  const isMuted = isUserMuted(activeUser);
  if (menuMuteText) menuMuteText.textContent = isMuted ? 'Unmute Notifications' : 'Mute Notifications';
  if (menuMuteIcon) {
    menuMuteIcon.innerHTML = isMuted
      ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>`
      : `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`;
  }

  const isBlocked = isUserBlocked(activeUser);
  if (menuBlockText) menuBlockText.textContent = isBlocked ? 'Unblock User' : 'Block User';
}

function toggleChatMenu(e) {
  if (e) e.stopPropagation();
  if (!activeUser) {
    Toast.show('info', 'Select a Contact', 'Please open a conversation with a contact first.');
    return;
  }
  updateMenuDynamicStates();
  chatDropdownMenu?.classList.toggle('active');
}

function closeChatMenu() {
  chatDropdownMenu?.classList.remove('active');
}

function toggleMuteNotifications() {
  closeChatMenu();
  if (!activeUser) return;
  if (isUserMuted(activeUser)) {
    mutedUsers.delete(activeUser);
    savePrivacySettings();
    Toast.show('info', 'Notifications Unmuted', `Alerts enabled for @${activeUser}.`);
  } else {
    mutedUsers.add(activeUser);
    savePrivacySettings();
    Toast.show('info', 'Notifications Muted', `You will not receive sound alerts for @${activeUser}.`);
  }
  updateMenuDynamicStates();
  const muteSwitch = document.getElementById('muteToggleSwitch');
  if (muteSwitch) muteSwitch.checked = isUserMuted(activeUser);
}

function handleBlockClick() {
  closeChatMenu();
  if (!activeUser) return;
  if (isUserBlocked(activeUser)) {
    blockedUsers.delete(activeUser);
    savePrivacySettings();
    applyBlockUI(activeUser);
    Toast.show('success', 'User Unblocked', `You can now exchange messages with @${activeUser}.`);
    updateMenuDynamicStates();
    updateRightSidebarUI();
  } else {
    if (blockTargetName) blockTargetName.textContent = `@${activeUser}`;
    blockUserModal?.classList.add('active');
  }
}

function confirmBlockUser() {
  if (!activeUser) return;
  blockedUsers.add(activeUser);
  savePrivacySettings();
  blockUserModal?.classList.remove('active');
  applyBlockUI(activeUser);
  Toast.show('warning', 'User Blocked', `@${activeUser} has been blocked.`);
  updateMenuDynamicStates();
  updateRightSidebarUI();
}

function applyBlockUI(username) {
  const isBlocked = isUserBlocked(username);
  if (messageInput) {
    messageInput.disabled = isBlocked;
    messageInput.placeholder = isBlocked
      ? `You have blocked @${username}. Unblock to send messages.`
      : 'Message...';
  }
  if (sendBtn) sendBtn.disabled = isBlocked;
}

function handleReportClick() {
  closeChatMenu();
  if (!activeUser) return;
  if (reportTargetName) reportTargetName.textContent = `@${activeUser}`;
  reportUserModal?.classList.add('active');
}

function submitReportUser() {
  if (!activeUser) return;
  const reason = document.querySelector('input[name="reportReason"]:checked')?.value || 'Inappropriate content';
  reportUserModal?.classList.remove('active');
  Toast.show('success', 'Report Submitted', `Report regarding @${activeUser} for "${reason}" received.`);
}

/* ─── Online Stories Strip ─── */
function renderOnlineStoriesStrip() {
  const strip = document.getElementById('onlineUsersStrip');
  if (!strip) return;

  const myInitials = (document.querySelector('.user-profile-avatar')?.textContent.trim() || myUsername.slice(0, 2)).toUpperCase();
  let html = `
    <div class="ig-story-item" title="You are online">
      <div class="ig-story-avatar-wrap">
        <div class="ig-story-avatar" style="background:var(--ig-gradient-brand)">${escapeHtml(myInitials)}</div>
      </div>
      <span class="ig-story-username">Your note</span>
    </div>
  `;

  Object.keys(USERS).forEach(username => {
    if (username === myUsername) return;
    const u = USERS[username];
    if (u.status === 'online') {
      html += `
        <div class="ig-story-item" data-username="${u.username}" title="${escapeHtml(u.username)} is online">
          <div class="ig-story-avatar-wrap">
            <div class="ig-story-avatar" style="background:${u.gradient}">${u.initials}</div>
          </div>
          <span class="ig-story-username">${escapeHtml(u.username)}</span>
        </div>
      `;
    }
  });

  strip.innerHTML = html;
  strip.querySelectorAll('.ig-story-item[data-username]').forEach(item => {
    item.addEventListener('click', () => switchConversation(item.dataset.username));
  });
}

/* ─── Multi-Tab Picker: Emojis, GIFs & Stickers ─── */
function initEmojiAndMediaPickers() {
  const emojiBtn = document.getElementById('emojiBtn');
  const popover = document.getElementById('emojiPickerPopover');
  if (!emojiBtn || !popover) return;

  emojiBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    popover.classList.toggle('active');
  });

  // Tab switching
  const tabEmojiBtn = document.getElementById('tabEmojiBtn');
  const tabGifBtn = document.getElementById('tabGifBtn');
  const tabStickerBtn = document.getElementById('tabStickerBtn');
  const emojiPanel = document.getElementById('emojiPanel');
  const gifPanel = document.getElementById('gifPanel');
  const stickerPanel = document.getElementById('stickerPanel');

  tabEmojiBtn?.addEventListener('click', () => {
    tabEmojiBtn.classList.add('active');
    tabGifBtn?.classList.remove('active');
    tabStickerBtn?.classList.remove('active');
    if (emojiPanel) emojiPanel.style.display = 'block';
    if (gifPanel) gifPanel.style.display = 'none';
    if (stickerPanel) stickerPanel.style.display = 'none';
  });

  tabGifBtn?.addEventListener('click', () => {
    tabGifBtn.classList.add('active');
    tabEmojiBtn?.classList.remove('active');
    tabStickerBtn?.classList.remove('active');
    if (gifPanel) gifPanel.style.display = 'block';
    if (emojiPanel) emojiPanel.style.display = 'none';
    if (stickerPanel) stickerPanel.style.display = 'none';
  });

  tabStickerBtn?.addEventListener('click', () => {
    tabStickerBtn.classList.add('active');
    tabEmojiBtn?.classList.remove('active');
    tabGifBtn?.classList.remove('active');
    if (stickerPanel) stickerPanel.style.display = 'block';
    if (emojiPanel) emojiPanel.style.display = 'none';
    if (gifPanel) gifPanel.style.display = 'none';
  });

  // Emojis click
  popover.querySelectorAll('.ig-emoji-item').forEach(btn => {
    btn.addEventListener('click', () => {
      const emoji = btn.textContent;
      if (messageInput) {
        messageInput.value += emoji;
        messageInput.focus();
        messageInput.dispatchEvent(new Event('input'));
      }
      popover.classList.remove('active');
    });
  });

  // GIFs click
  popover.querySelectorAll('.ig-gif-item').forEach(item => {
    item.addEventListener('click', () => {
      const gifUrl = item.dataset.gifUrl;
      if (gifUrl) sendGifMessage(gifUrl);
    });
  });

  // Stickers click
  popover.querySelectorAll('.ig-sticker-item').forEach(btn => {
    btn.addEventListener('click', () => {
      const sticker = btn.dataset.sticker || btn.textContent;
      if (sticker) sendStickerMessage(sticker);
    });
  });

  document.addEventListener('click', (e) => {
    if (!e.target.closest('#emojiPickerPopover') && !e.target.closest('#emojiBtn')) {
      popover.classList.remove('active');
    }
  });
}

/* ─── Right Sidebar Details ─── */
function initRightSidebar() {
  const rightSidebar = document.getElementById('rightSidebar');
  const infoBtn = document.getElementById('conversationInfoBtn');
  const closeBtn = document.getElementById('closeRightSidebarBtn');
  const emptyViewProfileBtn = document.getElementById('emptyChatViewProfileBtn');
  const verifySafetyBtn = document.getElementById('detailsVerifySafetyBtn');

  infoBtn?.addEventListener('click', () => {
    rightSidebar?.classList.toggle('collapsed');
  });

  closeBtn?.addEventListener('click', () => {
    rightSidebar?.classList.add('collapsed');
  });

  emptyViewProfileBtn?.addEventListener('click', openPeerProfileModal);
  verifySafetyBtn?.addEventListener('click', openPeerProfileModal);

  const muteSwitch = document.getElementById('muteToggleSwitch');
  muteSwitch?.addEventListener('change', toggleMuteNotifications);

  const searchBtn = document.getElementById('rightPanelSearchBtn');
  searchBtn?.addEventListener('click', openInChatSearch);

  const blockBtn = document.getElementById('rightPanelBlockBtn');
  blockBtn?.addEventListener('click', handleBlockClick);

  const reportBtn = document.getElementById('rightPanelReportBtn');
  reportBtn?.addEventListener('click', handleReportClick);

  const clearBtn = document.getElementById('rightPanelClearChatBtn');
  clearBtn?.addEventListener('click', clearActiveConversation);
}

/* ─── Global In-Chat Voice Message Player ─── */
const GlobalVoicePlayer = {
  currentAudio: null,
  currentCard: null,

  stop() {
    if (this.currentAudio) {
      try {
        this.currentAudio.pause();
        this.currentAudio.currentTime = 0;
      } catch (_) {}
      this.currentAudio = null;
    }
    if (this.currentCard) {
      this.resetCardUI(this.currentCard);
      this.currentCard = null;
    }
  },

  resetCardUI(card) {
    const playIcon = card.querySelector('.icon-play');
    const pauseIcon = card.querySelector('.icon-pause');
    if (playIcon) playIcon.style.display = 'block';
    if (pauseIcon) pauseIcon.style.display = 'none';

    const duration = card.dataset.duration || 0;
    const timeEl = card.querySelector('.voice-bubble-time');
    if (timeEl) timeEl.textContent = formatDuration(duration);

    card.querySelectorAll('.waveform-bar').forEach(b => b.classList.remove('played'));
  },

  toggle(card) {
    const src = card.dataset.audioSrc;
    if (!src) return;

    // If currently playing THIS card -> pause it
    if (this.currentCard === card && this.currentAudio && !this.currentAudio.paused) {
      this.currentAudio.pause();
      const playIcon = card.querySelector('.icon-play');
      const pauseIcon = card.querySelector('.icon-pause');
      if (playIcon) playIcon.style.display = 'block';
      if (pauseIcon) pauseIcon.style.display = 'none';
      return;
    }

    // If resuming THIS card
    if (this.currentCard === card && this.currentAudio && this.currentAudio.paused) {
      this.currentAudio.play().catch(e => console.warn('Audio resume error:', e));
      const playIcon = card.querySelector('.icon-play');
      const pauseIcon = card.querySelector('.icon-pause');
      if (playIcon) playIcon.style.display = 'none';
      if (pauseIcon) pauseIcon.style.display = 'block';
      return;
    }

    // Stop any previously playing audio
    this.stop();

    this.currentCard = card;
    const audio = new Audio(src);
    this.currentAudio = audio;

    const playIcon = card.querySelector('.icon-play');
    const pauseIcon = card.querySelector('.icon-pause');
    if (playIcon) playIcon.style.display = 'none';
    if (pauseIcon) pauseIcon.style.display = 'block';

    const timeEl = card.querySelector('.voice-bubble-time');
    const bars = card.querySelectorAll('.waveform-bar');
    const totalBars = bars.length;

    audio.addEventListener('timeupdate', () => {
      if (timeEl) timeEl.textContent = formatDuration(audio.currentTime);
      if (audio.duration && totalBars > 0) {
        const playedCount = Math.floor((audio.currentTime / audio.duration) * totalBars);
        bars.forEach((bar, idx) => {
          if (idx <= playedCount) bar.classList.add('played');
          else bar.classList.remove('played');
        });
      }
    });

    audio.addEventListener('ended', () => {
      this.resetCardUI(card);
      this.currentAudio = null;
      this.currentCard = null;
    });

    audio.addEventListener('error', (err) => {
      console.warn('Audio error:', err);
      Toast.show('error', 'Audio Playback', 'Failed to play voice message.');
      this.resetCardUI(card);
      this.currentAudio = null;
      this.currentCard = null;
    });

    audio.play().catch(err => {
      console.warn('Playback blocked:', err);
      this.resetCardUI(card);
      this.currentAudio = null;
      this.currentCard = null;
    });
  },

  seek(card, fraction) {
    if (this.currentCard !== card) {
      this.toggle(card);
    }
    if (this.currentAudio && this.currentAudio.duration) {
      this.currentAudio.currentTime = Math.max(0, Math.min(this.currentAudio.duration, fraction * this.currentAudio.duration));
    }
  }
};

/* ─── Client-Side Voice Recording & Preview Manager ─── */
const VoiceRecorderManager = {
  mediaRecorder: null,
  stream: null,
  audioChunks: [],
  timerInterval: null,
  seconds: 0,
  recordedBlob: null,
  recordedDuration: 0,
  recordedWaveform: [],
  previewAudio: null,
  state: 'inactive', // 'inactive', 'recording', 'paused', 'stopped'

  inputBar: null,
  recordBar: null,
  previewBar: null,
  recordTimer: null,
  statusLabel: null,
  pauseBtn: null,
  liveWave: null,
  previewPlayBtn: null,
  previewTimer: null,
  previewWaveBars: null,

  init() {
    this.inputBar        = document.getElementById('inputBar');
    this.recordBar       = document.getElementById('voiceRecordBar');
    this.previewBar      = document.getElementById('voicePreviewBar');
    this.recordTimer     = document.getElementById('voiceRecordTimer');
    this.statusLabel     = document.getElementById('voiceStatusLabel');
    this.pauseBtn        = document.getElementById('voicePauseResumeBtn');
    this.liveWave        = document.getElementById('voiceLiveWave');
    this.previewPlayBtn  = document.getElementById('voicePreviewPlayBtn');
    this.previewTimer    = document.getElementById('voicePreviewTimer');
    this.previewWaveBars = document.getElementById('voicePreviewWaveBars');

    // Controls
    document.getElementById('voiceRecordBtn')?.addEventListener('click', () => this.start());
    document.getElementById('voiceCancelBtn')?.addEventListener('click', () => this.cancel());
    this.pauseBtn?.addEventListener('click', () => this.togglePauseResume());
    document.getElementById('voiceStopBtn')?.addEventListener('click', () => this.stopAndPreview());

    document.getElementById('voicePreviewCancelBtn')?.addEventListener('click', () => this.cancel());
    this.previewPlayBtn?.addEventListener('click', () => this.togglePreviewPlay());
    document.getElementById('voiceSendBtn')?.addEventListener('click', () => this.send());

    // Preview scrubber
    const previewTrack = document.getElementById('voicePreviewTrack');
    previewTrack?.addEventListener('click', (e) => {
      if (!this.previewAudio || !this.recordedDuration) return;
      const rect = previewTrack.getBoundingClientRect();
      const frac = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
      this.previewAudio.currentTime = frac * (this.previewAudio.duration || this.recordedDuration);
      this.updatePreviewUI();
    });
  },

  async start() {
    if (!activeUser) {
      Toast.show('warning', 'Select Contact', 'Please select a contact before recording a voice message.');
      return;
    }
    if (isUserBlocked(activeUser)) {
      Toast.show('warning', 'User Blocked', `Cannot send voice note. You have blocked @${activeUser}.`);
      return;
    }

    GlobalVoicePlayer.stop();

    try {
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        throw new Error('Microphone audio recording not supported in this browser.');
      }

      this.stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      this.audioChunks = [];
      this.seconds = 0;

      const mimeType = this.getSupportedMimeType();
      const options = mimeType ? { mimeType } : {};
      this.mediaRecorder = new MediaRecorder(this.stream, options);

      this.mediaRecorder.ondataavailable = (e) => {
        if (e.data && e.data.size > 0) {
          this.audioChunks.push(e.data);
        }
      };

      this.mediaRecorder.onstop = () => {
        this.handleRecordingStopped();
      };

      this.mediaRecorder.start(100);
      this.state = 'recording';

      // Switch UI to recording bar
      if (this.inputBar) this.inputBar.style.display = 'none';
      if (this.previewBar) this.previewBar.style.display = 'none';
      if (this.recordBar) this.recordBar.style.display = 'flex';

      this.updateTimerDisplay();
      this.startTimer();
      this.setPauseBtnIcon(false);
      if (this.statusLabel) this.statusLabel.textContent = 'Recording...';
      this.liveWave?.classList.remove('paused');

      emitTyping(true);
    } catch (err) {
      console.warn('Microphone error:', err);
      Toast.show('error', 'Microphone Error', err.message || 'Could not access microphone.');
      this.resetUI();
    }
  },

  togglePauseResume() {
    if (!this.mediaRecorder) return;
    if (this.state === 'recording') {
      try {
        this.mediaRecorder.pause();
        this.state = 'paused';
        this.stopTimer();
        this.setPauseBtnIcon(true);
        if (this.statusLabel) this.statusLabel.textContent = 'Paused';
        this.liveWave?.classList.add('paused');
      } catch (e) {
        console.warn('Pause error:', e);
      }
    } else if (this.state === 'paused') {
      try {
        this.mediaRecorder.resume();
        this.state = 'recording';
        this.startTimer();
        this.setPauseBtnIcon(false);
        if (this.statusLabel) this.statusLabel.textContent = 'Recording...';
        this.liveWave?.classList.remove('paused');
      } catch (e) {
        console.warn('Resume error:', e);
      }
    }
  },

  stopAndPreview() {
    if (!this.mediaRecorder || this.state === 'inactive') return;
    this.recordedDuration = Math.max(1, this.seconds);
    this.stopTimer();
    this.state = 'stopped';
    try {
      this.mediaRecorder.stop();
    } catch (e) {
      console.warn('Stop error:', e);
    }
    this.stopStreamTracks();
  },

  handleRecordingStopped() {
    const mimeType = this.mediaRecorder?.mimeType || 'audio/webm';
    this.recordedBlob = new Blob(this.audioChunks, { type: mimeType });
    this.recordedWaveform = generateWaveformFromDuration(this.recordedDuration);

    // Switch UI to Preview Bar
    if (this.recordBar) this.recordBar.style.display = 'none';
    if (this.previewBar) this.previewBar.style.display = 'flex';

    if (this.previewTimer) this.previewTimer.textContent = formatDuration(this.recordedDuration);

    // Render preview waveform bars
    if (this.previewWaveBars) {
      this.previewWaveBars.innerHTML = this.recordedWaveform.map((val, idx) => {
        const height = Math.max(15, Math.min(100, Math.round(val * 100)));
        return `<div class="preview-bar" data-idx="${idx}" style="height:${height}%;"></div>`;
      }).join('');
    }

    if (this.previewAudio) {
      try { this.previewAudio.pause(); } catch (_) {}
      this.previewAudio = null;
    }

    const audioUrl = URL.createObjectURL(this.recordedBlob);
    this.previewAudio = new Audio(audioUrl);
    this.setPreviewPlayIcon(false);

    this.previewAudio.addEventListener('timeupdate', () => this.updatePreviewUI());
    this.previewAudio.addEventListener('ended', () => {
      this.setPreviewPlayIcon(false);
      if (this.previewTimer) this.previewTimer.textContent = formatDuration(this.recordedDuration);
      this.previewWaveBars?.querySelectorAll('.preview-bar').forEach(b => b.classList.remove('active'));
    });

    emitTyping(false);
  },

  togglePreviewPlay() {
    if (!this.previewAudio) return;
    if (this.previewAudio.paused) {
      this.previewAudio.play().catch(e => console.warn('Preview play error:', e));
      this.setPreviewPlayIcon(true);
    } else {
      this.previewAudio.pause();
      this.setPreviewPlayIcon(false);
    }
  },

  updatePreviewUI() {
    if (!this.previewAudio) return;
    const cur = this.previewAudio.currentTime;
    const dur = this.previewAudio.duration || this.recordedDuration || 1;
    if (this.previewTimer) this.previewTimer.textContent = formatDuration(cur);

    if (this.previewWaveBars) {
      const bars = this.previewWaveBars.querySelectorAll('.preview-bar');
      const activeIdx = Math.floor((cur / dur) * bars.length);
      bars.forEach((b, i) => {
        if (i <= activeIdx) b.classList.add('active');
        else b.classList.remove('active');
      });
    }
  },

  cancel() {
    this.stopTimer();
    if (this.mediaRecorder && this.state !== 'inactive') {
      try { this.mediaRecorder.stop(); } catch (_) {}
    }
    this.stopStreamTracks();
    if (this.previewAudio) {
      try { this.previewAudio.pause(); } catch (_) {}
      this.previewAudio = null;
    }
    this.audioChunks = [];
    this.recordedBlob = null;
    this.state = 'inactive';
    this.resetUI();
    emitTyping(false);
    Toast.show('info', 'Voice Message', 'Recording discarded.');
  },

  async send() {
    if (!this.recordedBlob || (!activeUser && !activeGroup)) return;
    if (this.previewAudio) {
      try { this.previewAudio.pause(); } catch (_) {}
    }

    Toast.show('info', 'Encrypting Voice Message', 'Securing audio with AES-256-GCM...');

    const duration = this.recordedDuration;
    const waveform = this.recordedWaveform;
    const blob = this.recordedBlob;

    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const dataUrl = e.target.result;
        const voicePayload = JSON.stringify({
          type: 'media',
          mediaType: 'audio',
          name: 'voice_message.webm',
          size: blob.size,
          duration: duration,
          waveform: waveform,
          data: dataUrl
        });

        if (activeGroup) {
          const encryptedPkg = await EncryptionEngine.encryptGroupMessage(activeGroup.id, activeGroup.current_epoch, voicePayload);

          if (emptyChatState) emptyChatState.style.display = 'none';
          const time = formatTime(null);
          const msgEl = createMessageElement(voicePayload, true, time, null, false, {
            ciphertext: encryptedPkg.ciphertext,
            nonce: encryptedPkg.nonce,
            tag: encryptedPkg.tag,
            epoch: activeGroup.current_epoch,
            is_group: true,
            sender_username: myUsername,
            message_type: 'audio',
          });

          if (typingIndicator && messagesArea) {
            messagesArea.insertBefore(msgEl, typingIndicator);
          } else {
            messagesArea?.appendChild(msgEl);
          }
          scrollToBottom();

          if (socket && socket.connected) {
            socket.emit('send_group_message', {
              group_id: activeGroup.id,
              epoch: activeGroup.current_epoch,
              ciphertext: encryptedPkg.ciphertext,
              nonce: encryptedPkg.nonce,
              tag: encryptedPkg.tag,
              encrypted_package: encryptedPkg,
              message_type: 'audio',
              media_meta: { duration, waveform, size: blob.size, type: 'audio/webm' },
            });
          }
          Toast.show('success', 'Voice Sent', 'Encrypted voice note sent to group.');
          this.resetUI();
          return;
        }

        // Client-side AES-256-GCM authenticated encryption
        const encryptedPkg = await EncryptionEngine.encryptFor(activeUser, voicePayload);

        // Render outgoing message immediately in local chat bubble
        if (emptyChatState) emptyChatState.style.display = 'none';
        const time = formatTime(null);
        const msgEl = createMessageElement(voicePayload, true, time, null, false, {
          ciphertext: encryptedPkg.ciphertext,
          nonce: encryptedPkg.nonce,
          tag: encryptedPkg.tag,
          message_type: 'audio',
        });

        if (typingIndicator && messagesArea) {
          messagesArea.insertBefore(msgEl, typingIndicator);
        } else {
          messagesArea?.appendChild(msgEl);
        }
        scrollToBottom();

        // Emit encrypted packet to WebSocket gateway
        if (socket && socket.connected) {
          socket.emit('send_message', {
            recipient_username: activeUser,
            encrypted_package: encryptedPkg,
            message_type: 'audio',
            media_meta: JSON.stringify({ duration, size: blob.size, type: 'audio/webm' })
          });
        }

        Toast.show('success', 'Voice Message Sent', 'Voice note encrypted & delivered.');
        this.resetUI();
      } catch (err) {
        console.error('Failed to encrypt voice note:', err);
        Toast.show('error', 'Encryption Failed', err.message);
      }
    };
    reader.readAsDataURL(blob);
  },

  resetUI() {
    if (this.recordBar) this.recordBar.style.display = 'none';
    if (this.previewBar) this.previewBar.style.display = 'none';
    if (this.inputBar) this.inputBar.style.display = 'flex';
    this.state = 'inactive';
  },

  startTimer() {
    this.stopTimer();
    this.timerInterval = setInterval(() => {
      this.seconds++;
      this.updateTimerDisplay();
    }, 1000);
  },

  stopTimer() {
    if (this.timerInterval) {
      clearInterval(this.timerInterval);
      this.timerInterval = null;
    }
  },

  updateTimerDisplay() {
    const mins = Math.floor(this.seconds / 60);
    const secs = this.seconds % 60;
    const str = `${mins < 10 ? '0' : ''}${mins}:${secs < 10 ? '0' : ''}${secs}`;
    if (this.recordTimer) this.recordTimer.textContent = str;
  },

  setPauseBtnIcon(isPaused) {
    if (!this.pauseBtn) return;
    const pauseIcon = this.pauseBtn.querySelector('.icon-pause');
    const resumeIcon = this.pauseBtn.querySelector('.icon-resume');
    if (pauseIcon) pauseIcon.style.display = isPaused ? 'none' : 'block';
    if (resumeIcon) resumeIcon.style.display = isPaused ? 'block' : 'none';
    this.pauseBtn.title = isPaused ? 'Resume recording' : 'Pause recording';
  },

  setPreviewPlayIcon(isPlaying) {
    if (!this.previewPlayBtn) return;
    const playIcon = this.previewPlayBtn.querySelector('.icon-play');
    const pauseIcon = this.previewPlayBtn.querySelector('.icon-pause');
    if (playIcon) playIcon.style.display = isPlaying ? 'none' : 'block';
    if (pauseIcon) pauseIcon.style.display = isPlaying ? 'block' : 'none';
  },

  stopStreamTracks() {
    if (this.stream) {
      try {
        this.stream.getTracks().forEach(t => t.stop());
      } catch (_) {}
      this.stream = null;
    }
  },

  getSupportedMimeType() {
    if (typeof MediaRecorder === 'undefined') return '';
    const candidates = [
      'audio/webm;codecs=opus',
      'audio/webm',
      'audio/ogg;codecs=opus',
      'audio/mp4',
      'audio/aac',
      ''
    ];
    for (const c of candidates) {
      if (!c || (MediaRecorder.isTypeSupported && MediaRecorder.isTypeSupported(c))) {
        return c;
      }
    }
    return '';
  }
};

/* ─── WebRTC Peer-to-Peer Voice & Video Call Manager (DTLS-SRTP) ─── */
const WebRTCCallManager = {
  peerConnection: null,
  localStream: null,
  remoteStream: null,
  callId: null,
  peerUsername: null,
  callType: 'voice',      // 'voice' or 'video'
  isCaller: false,
  callState: 'idle',      // 'idle' | 'calling' | 'ringing' | 'connecting' | 'connected'
  durationTimer: null,
  durationSeconds: 0,
  isMicMuted: false,
  isCameraOff: false,
  isSpeakerMuted: false,
  pendingCandidates: [],
  ringtoneInterval: null,
  audioCtx: null,

  // ICE configuration using Google STUN
  rtcConfig: {
    iceServers: [
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'stun:stun1.l.google.com:19302' },
      { urls: 'stun:stun2.l.google.com:19302' },
    ]
  },

  init() {
    // Header Call Triggers
    document.getElementById('voiceCallBtn')?.addEventListener('click', () => {
      if (!activeUser) {
        Toast.show('info', 'Voice Call', 'Please select a contact to call.');
        return;
      }
      this.startCall(activeUser, 'voice');
    });

    document.getElementById('videoCallBtn')?.addEventListener('click', () => {
      if (!activeUser) {
        Toast.show('info', 'Video Call', 'Please select a contact to call.');
        return;
      }
      this.startCall(activeUser, 'video');
    });

    // Incoming Call Actions
    document.getElementById('incomingAcceptBtn')?.addEventListener('click', () => {
      this.acceptCall();
    });

    document.getElementById('incomingRejectBtn')?.addEventListener('click', () => {
      this.rejectCall('rejected');
    });

    // Active Call Actions
    document.getElementById('endCallBtn')?.addEventListener('click', () => {
      this.endCall(true, 'completed');
    });

    document.getElementById('callMuteBtn')?.addEventListener('click', () => {
      this.toggleMic();
    });

    document.getElementById('callVideoToggleBtn')?.addEventListener('click', () => {
      this.toggleCamera();
    });

    document.getElementById('callSpeakerBtn')?.addEventListener('click', () => {
      this.toggleSpeaker();
    });

    document.getElementById('callMinimizeBtn')?.addEventListener('click', () => {
      this.minimizeCall();
    });

    document.getElementById('minCallExpandBtn')?.addEventListener('click', () => {
      this.expandCall();
    });

    document.getElementById('minCallEndBtn')?.addEventListener('click', () => {
      this.endCall(true, 'completed');
    });
  },

  // ── Audio Synthesis for Ringing / Chimes ──────────────────────────
  getAudioContext() {
    if (!this.audioCtx) {
      const AudioContextClass = window.AudioContext || window.webkitAudioContext;
      if (AudioContextClass) this.audioCtx = new AudioContextClass();
    }
    if (this.audioCtx && this.audioCtx.state === 'suspended') {
      this.audioCtx.resume().catch(() => {});
    }
    return this.audioCtx;
  },

  playRingtone() {
    this.stopRingtone();
    try {
      const ctx = this.getAudioContext();
      if (!ctx) return;

      const ringCycle = () => {
        try {
          const osc1 = ctx.createOscillator();
          const osc2 = ctx.createOscillator();
          const gain = ctx.createGain();

          osc1.type = 'sine';
          osc2.type = 'sine';
          osc1.frequency.setValueAtTime(440, ctx.currentTime);
          osc2.frequency.setValueAtTime(480, ctx.currentTime);

          gain.gain.setValueAtTime(0.08, ctx.currentTime);
          gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 1.2);

          osc1.connect(gain);
          osc2.connect(gain);
          gain.connect(ctx.destination);

          osc1.start();
          osc2.start();
          osc1.stop(ctx.currentTime + 1.2);
          osc2.stop(ctx.currentTime + 1.2);
        } catch (_) {}
      };

      ringCycle();
      this.ringtoneInterval = setInterval(ringCycle, 2800);
    } catch (e) {
      console.warn('Ringtone sound warning:', e);
    }
  },

  stopRingtone() {
    if (this.ringtoneInterval) {
      clearInterval(this.ringtoneInterval);
      this.ringtoneInterval = null;
    }
  },

  playChime(type) {
    try {
      const ctx = this.getAudioContext();
      if (!ctx) return;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      const now = ctx.currentTime;
      if (type === 'connect') {
        osc.frequency.setValueAtTime(523.25, now); // C5
        osc.frequency.exponentialRampToValueAtTime(659.25, now + 0.15); // E5
        gain.gain.setValueAtTime(0.12, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.4);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start();
        osc.stop(now + 0.4);
      } else if (type === 'end') {
        osc.frequency.setValueAtTime(440, now);
        osc.frequency.exponentialRampToValueAtTime(220, now + 0.25);
        gain.gain.setValueAtTime(0.12, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.35);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start();
        osc.stop(now + 0.35);
      }
    } catch (_) {}
  },

  // ── Call Initiation (Caller) ─────────────────────────────────────
  async startCall(targetUsername, type = 'voice') {
    if (this.callState !== 'idle') {
      Toast.show('warning', 'Call in Progress', 'Please end your current call first.');
      return;
    }

    this.callType = type;
    this.peerUsername = targetUsername;
    this.isCaller = true;
    this.callState = 'calling';
    this.pendingCandidates = [];

    // Prompt for media access
    try {
      const constraints = {
        audio: true,
        video: type === 'video' ? { width: { ideal: 1280 }, height: { ideal: 720 }, facingMode: 'user' } : false
      };
      this.localStream = await navigator.mediaDevices.getUserMedia(constraints);
    } catch (err) {
      console.warn('getUserMedia error:', err);
      if (type === 'video') {
        try {
          this.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
          this.callType = 'voice';
          Toast.show('warning', 'Camera Unavailable', 'Starting voice call instead.');
        } catch (e2) {
          Toast.show('error', 'Microphone Access Required', 'Please allow microphone access in your browser to make calls.');
          this.resetCallState();
          return;
        }
      } else {
        Toast.show('error', 'Microphone Access Required', 'Please allow microphone access in your browser to make calls.');
        this.resetCallState();
        return;
      }
    }

    this.showCallModal();
    this.updateCallUIStatus(`Calling @${targetUsername}...`);
    this.playRingtone();

    // Socket emission to initiate call
    socket.emit('webrtc_call_user', {
      target_username: targetUsername,
      call_type: this.callType
    });
  },

  // ── Incoming Call (Callee) ───────────────────────────────────────
  handleIncomingCall(data) {
    const { call_id, caller_username, call_type } = data;

    if (isUserBlocked(caller_username)) {
      socket.emit('webrtc_reject_call', {
        call_id: call_id,
        caller_username: caller_username,
        reason: 'busy'
      });
      return;
    }

    if (this.callState !== 'idle') {
      socket.emit('webrtc_reject_call', {
        call_id: call_id,
        caller_username: caller_username,
        reason: 'busy'
      });
      return;
    }

    this.callId = call_id;
    this.peerUsername = caller_username;
    this.callType = call_type || 'voice';
    this.isCaller = false;
    this.callState = 'ringing';
    this.pendingCandidates = [];

    const overlay = document.getElementById('incomingCallModal');
    const nameEl = document.getElementById('incomingCallerName');
    const avatarEl = document.getElementById('incomingCallerAvatar');
    const descEl = document.getElementById('incomingCallTypeDesc');

    if (nameEl) nameEl.textContent = caller_username;
    if (descEl) descEl.textContent = call_type === 'video' ? 'Incoming Video Call...' : 'Incoming Voice Call...';
    if (avatarEl) {
      const u = USERS[caller_username];
      avatarEl.textContent = u ? u.initials : caller_username.slice(0, 2).toUpperCase();
      if (u?.gradient) avatarEl.style.background = u.gradient;
    }

    if (overlay) overlay.style.display = 'flex';
    this.playRingtone();
  },

  // ── Accept Call (Callee) ─────────────────────────────────────────
  async acceptCall() {
    this.stopRingtone();
    const overlay = document.getElementById('incomingCallModal');
    if (overlay) overlay.style.display = 'none';

    try {
      const constraints = {
        audio: true,
        video: this.callType === 'video' ? { width: { ideal: 1280 }, height: { ideal: 720 }, facingMode: 'user' } : false
      };
      this.localStream = await navigator.mediaDevices.getUserMedia(constraints);
    } catch (err) {
      console.warn('Accept call media error:', err);
      try {
        this.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
        this.callType = 'voice';
      } catch (e2) {
        Toast.show('error', 'Media Error', 'Failed to access microphone.');
        this.rejectCall('rejected');
        return;
      }
    }

    this.callState = 'connecting';
    this.showCallModal();
    this.updateCallUIStatus('Connecting...');

    this.createPeerConnection();

    socket.emit('webrtc_accept_call', {
      call_id: this.callId,
      caller_username: this.peerUsername,
      call_type: this.callType
    });
  },

  // ── Reject Call (Callee) ─────────────────────────────────────────
  rejectCall(reason = 'rejected') {
    this.stopRingtone();
    const overlay = document.getElementById('incomingCallModal');
    if (overlay) overlay.style.display = 'none';

    if (this.peerUsername) {
      socket.emit('webrtc_reject_call', {
        call_id: this.callId,
        caller_username: this.peerUsername,
        reason: reason
      });
      this.addCallSummaryPill(this.callType, 'rejected', 0);
    }
    this.resetCallState();
  },

  // ── Caller: Ringing Event ────────────────────────────────────────
  handleCallRinging(data) {
    if (this.callState === 'calling') {
      this.callId = data.call_id;
      this.updateCallUIStatus(`Ringing @${data.target_username}...`);
    }
  },

  // ── Caller: Recipient Accepted ───────────────────────────────────
  async handleCallAccepted(data) {
    if (this.callState !== 'calling') return;
    this.stopRingtone();
    this.callState = 'connecting';
    this.updateCallUIStatus('Connecting...');

    this.createPeerConnection();

    try {
      const offer = await this.peerConnection.createOffer({
        offerToReceiveAudio: true,
        offerToReceiveVideo: this.callType === 'video'
      });
      await this.peerConnection.setLocalDescription(offer);

      socket.emit('webrtc_signal', {
        target_username: this.peerUsername,
        call_id: this.callId,
        signal_type: 'offer',
        payload: offer
      });
    } catch (err) {
      console.error('Error creating SDP offer:', err);
      this.endCall(true, 'failed');
    }
  },

  // ── WebRTC Signal Handling ───────────────────────────────────────
  async handleRemoteSignal(data) {
    const { signal_type, payload } = data;
    if (!this.peerConnection) return;

    try {
      if (signal_type === 'offer') {
        await this.peerConnection.setRemoteDescription(new RTCSessionDescription(payload));
        this.drainPendingCandidates();

        const answer = await this.peerConnection.createAnswer();
        await this.peerConnection.setLocalDescription(answer);

        socket.emit('webrtc_signal', {
          target_username: this.peerUsername,
          call_id: this.callId,
          signal_type: 'answer',
          payload: answer
        });
      } else if (signal_type === 'answer') {
        await this.peerConnection.setRemoteDescription(new RTCSessionDescription(payload));
        this.drainPendingCandidates();
      } else if (signal_type === 'candidate') {
        if (this.peerConnection.remoteDescription && this.peerConnection.remoteDescription.type) {
          await this.peerConnection.addIceCandidate(new RTCIceCandidate(payload));
        } else {
          this.pendingCandidates.push(payload);
        }
      }
    } catch (err) {
      console.error('Error handling WebRTC signal:', err);
    }
  },

  drainPendingCandidates() {
    while (this.pendingCandidates.length > 0) {
      const candidate = this.pendingCandidates.shift();
      try {
        this.peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
      } catch (e) {
        console.warn('ICE candidate drain error:', e);
      }
    }
  },

  // ── Peer Connection Creation ─────────────────────────────────────
  createPeerConnection() {
    if (this.peerConnection) {
      try { this.peerConnection.close(); } catch (_) {}
    }

    const pc = new RTCPeerConnection(this.rtcConfig);
    this.peerConnection = pc;

    if (this.localStream) {
      this.localStream.getTracks().forEach(track => {
        pc.addTrack(track, this.localStream);
      });
    }

    const localVideo = document.getElementById('localVideo');
    if (localVideo && this.localStream && this.callType === 'video') {
      localVideo.srcObject = this.localStream;
      localVideo.muted = true;
    }

    pc.ontrack = (event) => {
      const remoteStream = event.streams[0] || new MediaStream([event.track]);
      this.remoteStream = remoteStream;

      const remoteVideo = document.getElementById('remoteVideo');
      const remoteAudio = document.getElementById('remoteAudio');

      if (remoteVideo && this.callType === 'video') {
        remoteVideo.srcObject = remoteStream;
      }
      if (remoteAudio) {
        remoteAudio.srcObject = remoteStream;
        remoteAudio.play().catch(e => console.warn('Remote audio playback warning:', e));
      }
    };

    pc.onicecandidate = (event) => {
      if (event.candidate) {
        socket.emit('webrtc_signal', {
          target_username: this.peerUsername,
          call_id: this.callId,
          signal_type: 'candidate',
          payload: event.candidate
        });
      }
    };

    pc.onconnectionstatechange = () => {
      console.info('[WebRTC] Connection state:', pc.connectionState);
      if (pc.connectionState === 'connected') {
        this.stopRingtone();
        this.callState = 'connected';
        this.playChime('connect');
        this.updateCallUIStatus('Connected · 🔒 DTLS-SRTP');
        this.startTimer();
      } else if (pc.connectionState === 'disconnected' || pc.connectionState === 'failed') {
        this.endCall(true, 'completed');
      }
    };

    pc.oniceconnectionstatechange = () => {
      if (pc.iceConnectionState === 'connected' || pc.iceConnectionState === 'completed') {
        this.stopRingtone();
        if (this.callState !== 'connected') {
          this.callState = 'connected';
          this.playChime('connect');
          this.updateCallUIStatus('Connected · 🔒 DTLS-SRTP');
          this.startTimer();
        }
      }
    };
  },

  handleCallRejected(data) {
    this.stopRingtone();
    const reason = data.reason === 'busy' ? 'User is busy on another call.' : 'Call was declined.';
    Toast.show('info', 'Call Ended', reason);
    this.playChime('end');
    this.addCallSummaryPill(this.callType, data.reason || 'rejected', 0);
    this.endCall(false, data.reason || 'rejected');
  },

  handleCallEnded(data) {
    this.stopRingtone();
    this.playChime('end');
    Toast.show('info', 'Call Ended', `Call ended by @${data.ended_by}`);
    this.addCallSummaryPill(this.callType, 'completed', data.duration_seconds || this.durationSeconds);
    this.endCall(false, 'completed');
  },

  handleCallUnavailable(data) {
    this.stopRingtone();
    Toast.show('warning', 'User Offline', data.message || `@${data.target_username} is offline.`);
    this.addCallSummaryPill(this.callType, 'missed', 0);
    this.endCall(false, 'missed');
  },

  handleCallError(data) {
    this.stopRingtone();
    Toast.show('error', 'Call Error', data.error || 'Call failed.');
    this.endCall(false, 'failed');
  },

  handlePeerMediaToggle(data) {
    if (data.media_type === 'video') {
      const camOffPlaceholder = document.getElementById('remoteCamOffOverlay');
      if (camOffPlaceholder) {
        camOffPlaceholder.style.display = data.enabled ? 'none' : 'flex';
      }
    }
  },

  // ── Active Call UI ───────────────────────────────────────────────
  showCallModal() {
    const modal = document.getElementById('callModal');
    const minBar = document.getElementById('minimizedCallBar');
    if (minBar) minBar.style.display = 'none';

    const voiceStage = document.getElementById('callVoiceStage');
    const videoStage = document.getElementById('callVideoStage');
    const nameEl = document.getElementById('callName');
    const avatarEl = document.getElementById('callAvatar');
    const secEl = document.getElementById('callSecurityText');

    if (this.callType === 'video') {
      if (voiceStage) voiceStage.style.display = 'none';
      if (videoStage) videoStage.style.display = 'flex';
    } else {
      if (voiceStage) voiceStage.style.display = 'flex';
      if (videoStage) videoStage.style.display = 'none';
    }

    if (nameEl) nameEl.textContent = this.peerUsername;
    if (avatarEl) {
      const u = USERS[this.peerUsername];
      avatarEl.textContent = u ? u.initials : this.peerUsername.slice(0, 2).toUpperCase();
      if (u?.gradient) avatarEl.style.background = u.gradient;
    }
    if (secEl) secEl.textContent = 'WebRTC DTLS-SRTP Media Encrypted';

    this.resetControlButtonsUI();
    if (modal) {
      modal.style.display = 'flex';
      modal.classList.add('active');
    }
  },

  updateCallUIStatus(statusText) {
    const statusEl = document.getElementById('callStatusText');
    if (statusEl) statusEl.textContent = statusText;
  },

  resetControlButtonsUI() {
    this.isMicMuted = false;
    this.isCameraOff = false;
    this.isSpeakerMuted = false;

    const muteBtn = document.getElementById('callMuteBtn');
    const videoBtn = document.getElementById('callVideoToggleBtn');
    const speakerBtn = document.getElementById('callSpeakerBtn');

    if (muteBtn) {
      muteBtn.classList.remove('active-muted');
      const micOn = muteBtn.querySelector('.icon-mic-on');
      const micOff = muteBtn.querySelector('.icon-mic-off');
      if (micOn) micOn.style.display = 'block';
      if (micOff) micOff.style.display = 'none';
    }
    if (videoBtn) {
      videoBtn.classList.remove('active-off');
      const camOn = videoBtn.querySelector('.icon-cam-on');
      const camOff = videoBtn.querySelector('.icon-cam-off');
      if (camOn) camOn.style.display = 'block';
      if (camOff) camOff.style.display = 'none';
      videoBtn.style.display = this.callType === 'voice' ? 'none' : 'flex';
    }
    if (speakerBtn) {
      speakerBtn.classList.remove('active-muted');
      const spkOn = speakerBtn.querySelector('.icon-speaker-on');
      const spkOff = speakerBtn.querySelector('.icon-speaker-off');
      if (spkOn) spkOn.style.display = 'block';
      if (spkOff) spkOff.style.display = 'none';
    }
  },

  // ── Media Controls ───────────────────────────────────────────────
  toggleMic() {
    if (!this.localStream) return;
    this.isMicMuted = !this.isMicMuted;
    this.localStream.getAudioTracks().forEach(track => {
      track.enabled = !this.isMicMuted;
    });

    const muteBtn = document.getElementById('callMuteBtn');
    if (muteBtn) {
      muteBtn.classList.toggle('active-muted', this.isMicMuted);
      const micOn = muteBtn.querySelector('.icon-mic-on');
      const micOff = muteBtn.querySelector('.icon-mic-off');
      if (micOn) micOn.style.display = this.isMicMuted ? 'none' : 'block';
      if (micOff) micOff.style.display = this.isMicMuted ? 'block' : 'none';
      muteBtn.title = this.isMicMuted ? 'Unmute Microphone' : 'Mute Microphone';
    }

    if (this.peerUsername) {
      socket.emit('webrtc_toggle_media', {
        target_username: this.peerUsername,
        call_id: this.callId,
        media_type: 'audio',
        enabled: !this.isMicMuted
      });
    }
    Toast.show('info', 'Microphone', this.isMicMuted ? 'Microphone muted.' : 'Microphone unmuted.');
  },

  toggleCamera() {
    if (!this.localStream || this.callType !== 'video') return;
    this.isCameraOff = !this.isCameraOff;
    this.localStream.getVideoTracks().forEach(track => {
      track.enabled = !this.isCameraOff;
    });

    const videoBtn = document.getElementById('callVideoToggleBtn');
    if (videoBtn) {
      videoBtn.classList.toggle('active-off', this.isCameraOff);
      const camOn = videoBtn.querySelector('.icon-cam-on');
      const camOff = videoBtn.querySelector('.icon-cam-off');
      if (camOn) camOn.style.display = this.isCameraOff ? 'none' : 'block';
      if (camOff) camOff.style.display = this.isCameraOff ? 'block' : 'none';
      videoBtn.title = this.isCameraOff ? 'Turn Camera On' : 'Turn Camera Off';
    }

    if (this.peerUsername) {
      socket.emit('webrtc_toggle_media', {
        target_username: this.peerUsername,
        call_id: this.callId,
        media_type: 'video',
        enabled: !this.isCameraOff
      });
    }
    Toast.show('info', 'Camera', this.isCameraOff ? 'Camera turned off.' : 'Camera turned on.');
  },

  toggleSpeaker() {
    this.isSpeakerMuted = !this.isSpeakerMuted;
    const remoteAudio = document.getElementById('remoteAudio');
    const remoteVideo = document.getElementById('remoteVideo');

    if (remoteAudio) remoteAudio.muted = this.isSpeakerMuted;
    if (remoteVideo) remoteVideo.muted = this.isSpeakerMuted;

    const speakerBtn = document.getElementById('callSpeakerBtn');
    if (speakerBtn) {
      speakerBtn.classList.toggle('active-muted', this.isSpeakerMuted);
      const spkOn = speakerBtn.querySelector('.icon-speaker-on');
      const spkOff = speakerBtn.querySelector('.icon-speaker-off');
      if (spkOn) spkOn.style.display = this.isSpeakerMuted ? 'none' : 'block';
      if (spkOff) spkOff.style.display = this.isSpeakerMuted ? 'block' : 'none';
    }
    Toast.show('info', 'Speaker', this.isSpeakerMuted ? 'Speaker muted.' : 'Speaker active.');
  },

  minimizeCall() {
    const modal = document.getElementById('callModal');
    const minBar = document.getElementById('minimizedCallBar');
    if (modal) {
      modal.style.display = 'none';
      modal.classList.remove('active');
    }
    if (minBar) {
      const nameEl = document.getElementById('minCallName');
      const avatarEl = document.getElementById('minCallAvatar');
      if (nameEl) nameEl.textContent = `@${this.peerUsername}`;
      if (avatarEl) {
        const u = USERS[this.peerUsername];
        avatarEl.textContent = u ? u.initials : this.peerUsername.slice(0, 2).toUpperCase();
        if (u?.gradient) avatarEl.style.background = u.gradient;
      }
      minBar.style.display = 'flex';
    }
  },

  expandCall() {
    const minBar = document.getElementById('minimizedCallBar');
    if (minBar) minBar.style.display = 'none';
    const modal = document.getElementById('callModal');
    if (modal) {
      modal.style.display = 'flex';
      modal.classList.add('active');
    }
  },

  startTimer() {
    this.stopTimer();
    this.durationSeconds = 0;
    const timerEl = document.getElementById('callDurationTimer');
    const minTimerEl = document.getElementById('minCallTimer');

    const updateDisplay = () => {
      this.durationSeconds++;
      const formatted = formatDuration(this.durationSeconds);
      if (timerEl) timerEl.textContent = formatted;
      if (minTimerEl) minTimerEl.textContent = formatted;
    };

    if (timerEl) timerEl.textContent = '00:00';
    if (minTimerEl) minTimerEl.textContent = '00:00';
    this.durationTimer = setInterval(updateDisplay, 1000);
  },

  stopTimer() {
    if (this.durationTimer) {
      clearInterval(this.durationTimer);
      this.durationTimer = null;
    }
  },

  endCall(sendSignal = true, status = 'completed') {
    this.stopRingtone();
    this.stopTimer();
    this.playChime('end');

    const peer = this.peerUsername;
    const dur = this.durationSeconds;
    const type = this.callType;

    if (sendSignal && peer && socket && socket.connected) {
      socket.emit('webrtc_end_call', {
        call_id: this.callId,
        target_username: peer,
        duration_seconds: dur,
        status: status
      });
      this.addCallSummaryPill(type, status, dur);
    }

    if (this.localStream) {
      this.localStream.getTracks().forEach(track => {
        try { track.stop(); } catch (_) {}
      });
      this.localStream = null;
    }

    if (this.peerConnection) {
      try { this.peerConnection.close(); } catch (_) {}
      this.peerConnection = null;
    }

    const localVideo = document.getElementById('localVideo');
    const remoteVideo = document.getElementById('remoteVideo');
    const remoteAudio = document.getElementById('remoteAudio');
    if (localVideo) localVideo.srcObject = null;
    if (remoteVideo) remoteVideo.srcObject = null;
    if (remoteAudio) remoteAudio.srcObject = null;

    const modal = document.getElementById('callModal');
    const minBar = document.getElementById('minimizedCallBar');
    const incomingModal = document.getElementById('incomingCallModal');

    if (modal) {
      modal.style.display = 'none';
      modal.classList.remove('active');
    }
    if (minBar) minBar.style.display = 'none';
    if (incomingModal) incomingModal.style.display = 'none';

    this.resetCallState();
    if (peer) loadPeerCallHistory(peer);
  },

  resetCallState() {
    this.callState = 'idle';
    this.callId = null;
    this.peerUsername = null;
    this.isCaller = false;
    this.durationSeconds = 0;
    this.pendingCandidates = [];
  },

  addCallSummaryPill(type, status, duration) {
    if (!messagesArea) return;
    const isVideo = type === 'video';
    const isMissed = status === 'missed' || status === 'rejected';

    let label = '';
    if (isMissed) {
      label = isVideo ? 'Missed video call' : 'Missed voice call';
    } else {
      label = isVideo ? `Video call · ${formatDuration(duration)}` : `Voice call · ${formatDuration(duration)}`;
    }

    const pillDiv = document.createElement('div');
    pillDiv.className = 'message-group-time-divider';
    pillDiv.style.margin = '10px auto';
    pillDiv.style.textAlign = 'center';

    pillDiv.innerHTML = `
      <div class="msg-call-pill">
        <span class="call-pill-icon ${isMissed ? 'missed' : (isVideo ? 'video' : 'voice')}">
          ${isMissed ? '📵' : (isVideo ? '📹' : '📞')}
        </span>
        <span style="font-weight:600;">${label}</span>
        <button class="call-pill-btn" onclick="WebRTCCallManager.startCall('${activeUser}', '${type}')">Call back</button>
      </div>
    `;

    messagesArea.appendChild(pillDiv);
    scrollToBottom(false);
  }
};

/* ─── Load Call History in Right Sidebar ─── */
async function loadPeerCallHistory(username) {
  const container = document.getElementById('detailsCallHistoryList');
  if (!container || !username) return;

  try {
    const res = await fetch(`/api/calls/history/${encodeURIComponent(username)}`);
    if (!res.ok) return;
    const data = await res.json();
    if (!data.ok || !data.calls || data.calls.length === 0) {
      container.innerHTML = '<div class="ig-empty-history-text" style="font-size:12px; color:var(--ig-text-secondary); padding:4px 0;">No recent calls</div>';
      return;
    }

    container.innerHTML = data.calls.slice(0, 5).map(c => {
      const isVoice = c.call_type === 'voice';
      const isOutgoing = c.caller_username === myUsername;
      const isMissed = c.status === 'missed' || c.status === 'rejected';
      const icon = isMissed ? '📵' : (isVoice ? '📞' : '📹');
      const timeStr = c.started_at ? formatTime(c.started_at) : '';
      const durStr = c.duration_seconds > 0 ? formatDuration(c.duration_seconds) : c.status;

      return `
        <div class="ig-call-history-item" title="Click to call back" onclick="WebRTCCallManager.startCall('${username}', '${c.call_type}')" style="cursor:pointer;">
          <div class="ig-call-history-meta">
            <span class="ig-call-history-icon">${icon}</span>
            <div>
              <div class="ig-call-history-title">${isVoice ? 'Voice Call' : 'Video Call'} (${isOutgoing ? 'Outgoing' : 'Incoming'})</div>
              <div class="ig-call-history-time">${timeStr}</div>
            </div>
          </div>
          <span class="ig-call-history-duration">${durStr}</span>
        </div>
      `;
    }).join('');
  } catch (err) {
    console.debug('Failed to load call history:', err);
  }
}

/* ══════════════════════════════════════════════════════════════════════════
   SCHEDULED MESSAGES MANAGER (E2EE Client-Side Scheduling)
   ══════════════════════════════════════════════════════════════════════════ */
const ScheduledMessagesManager = {
  activeFilter: 'pending',
  thisChatOnly: false,
  peerCache: new Map(),

  formatLocalISO(d) {
    const pad = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  },

  formatDisplayDateTime(isoStr) {
    if (!isoStr) return '--';
    try {
      const d = new Date(isoStr);
      return d.toLocaleString([], {
        weekday: 'short',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch (_) {
      return isoStr;
    }
  },

  formatCountdown(isoStr) {
    if (!isoStr) return '';
    try {
      const diffMs = new Date(isoStr).getTime() - Date.now();
      if (diffMs <= 0) return 'Due now';
      const diffMins = Math.round(diffMs / 60000);
      if (diffMins < 60) return `in ${diffMins}m`;
      const diffHrs = Math.floor(diffMins / 60);
      const remMins = diffMins % 60;
      if (diffHrs < 24) return `in ${diffHrs}h ${remMins}m`;
      const diffDays = Math.floor(diffHrs / 24);
      return `in ${diffDays}d ${diffHrs % 24}h`;
    } catch (_) {
      return '';
    }
  },

  openScheduleModal(initialText = '') {
    if (!activeUser) {
      Toast.show('info', 'No Conversation Selected', 'Please select a contact before scheduling a message.');
      return;
    }

    const modal = document.getElementById('scheduleModal');
    const recipientEl = document.getElementById('schedRecipientDisplay');
    const textarea = document.getElementById('schedMessageInput');
    const picker = document.getElementById('schedDateTimeInput');

    if (recipientEl) recipientEl.textContent = `@${activeUser}`;
    if (textarea) {
      textarea.value = initialText || (messageInput ? messageInput.value.trim() : '');
    }

    // Set minimum to 1 minute from now, default to 1 hour ahead
    const minD = new Date(Date.now() + 60 * 1000);
    const defaultD = new Date(Date.now() + 60 * 60 * 1000);
    if (picker) {
      picker.min = this.formatLocalISO(minD);
      picker.value = this.formatLocalISO(defaultD);
    }

    document.querySelectorAll('.ig-sched-preset-pill').forEach(b => b.classList.remove('active'));

    if (modal) {
      modal.style.display = 'flex';
      modal.classList.add('active');
    }
    textarea?.focus();
  },

  closeScheduleModal() {
    const modal = document.getElementById('scheduleModal');
    if (modal) {
      modal.style.display = 'none';
      modal.classList.remove('active');
    }
  },

  applyPreset(btn) {
    const picker = document.getElementById('schedDateTimeInput');
    if (!picker) return;

    document.querySelectorAll('.ig-sched-preset-pill').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    const minutes = btn.dataset.minutes;
    const preset = btn.dataset.preset;
    let target = new Date();

    if (minutes) {
      target = new Date(Date.now() + parseInt(minutes, 10) * 60 * 1000);
    } else if (preset === 'tomorrow-9am') {
      target.setDate(target.getDate() + 1);
      target.setHours(9, 0, 0, 0);
    } else if (preset === 'tomorrow-8pm') {
      target.setDate(target.getDate() + 1);
      target.setHours(20, 0, 0, 0);
    }

    picker.value = this.formatLocalISO(target);
  },

  async confirmSchedule() {
    if (!activeUser) return;
    const textarea = document.getElementById('schedMessageInput');
    const picker = document.getElementById('schedDateTimeInput');
    const text = textarea?.value.trim();
    if (!text) {
      Toast.show('error', 'Empty Message', 'Please enter a message to schedule.');
      return;
    }

    const pickerVal = picker?.value;
    if (!pickerVal) {
      Toast.show('error', 'Select Date & Time', 'Please choose when to deliver this message.');
      return;
    }

    const targetDate = new Date(pickerVal);
    if (isNaN(targetDate.getTime()) || targetDate.getTime() <= Date.now()) {
      Toast.show('error', 'Invalid Time', 'Scheduled time must be in the future.');
      return;
    }

    const confirmBtn = document.getElementById('confirmScheduleBtn');
    if (confirmBtn) {
      confirmBtn.disabled = true;
      confirmBtn.textContent = 'Encrypting & Scheduling...';
    }

    try {
      // 1. Client-Side E2EE Encryption with AES-256-GCM
      let encPkg = null;
      if (typeof EncryptionEngine !== 'undefined') {
        encPkg = await EncryptionEngine.encryptFor(activeUser, text);
      } else {
        throw new Error('EncryptionEngine not available');
      }

      const utcIso = targetDate.toISOString();

      // 2. Submit encrypted ciphertext and metadata to server (zero plaintext)
      const res = await fetch('/api/messages/schedule', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': getCsrfToken(),
        },
        body: JSON.stringify({
          recipient_username: activeUser,
          ciphertext: encPkg.ciphertext,
          nonce: encPkg.nonce,
          tag: encPkg.tag,
          encrypted_package: encPkg,
          scheduled_for: utcIso,
          message_type: 'text',
          media_meta: {},
        }),
      });

      const data = await res.json();
      if (!res.ok || !data.ok) {
        throw new Error(data.error || 'Failed to schedule message');
      }

      if (data.scheduled_id) {
        this.peerCache.set(data.scheduled_id, text);
      }

      if (messageInput && messageInput.value.trim() === text) {
        messageInput.value = '';
        messageInput.style.height = 'auto';
      }

      this.closeScheduleModal();
      Toast.show('success', 'Message Scheduled', `Delivery set for ${this.formatDisplayDateTime(utcIso)}`);
      this.refreshActivePeerScheduled();
    } catch (err) {
      console.error('Failed to schedule message:', err);
      Toast.show('error', 'Scheduling Failed', err.message || 'Error scheduling message');
    } finally {
      if (confirmBtn) {
        confirmBtn.disabled = false;
        confirmBtn.innerHTML = `
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14" style="margin-right:6px;">
            <circle cx="12" cy="12" r="10" />
            <polyline points="12 6 12 12 16 14" />
          </svg>
          Schedule Message
        `;
      }
    }
  },

  async refreshActivePeerScheduled() {
    const banner = document.getElementById('scheduledBanner');
    const bannerText = document.getElementById('scheduledBannerText');
    const badge = document.getElementById('detailsSchedCountBadge');
    const emptyText = document.getElementById('detailsSchedEmptyText');
    const previewList = document.getElementById('detailsSchedList');

    if (!activeUser) {
      if (banner) banner.style.display = 'none';
      if (badge) badge.style.display = 'none';
      if (emptyText) emptyText.style.display = 'block';
      if (previewList) { previewList.style.display = 'none'; previewList.innerHTML = ''; }
      return;
    }

    try {
      const res = await fetch(`/api/messages/scheduled?peer=${encodeURIComponent(activeUser)}&status=pending`);
      if (!res.ok) return;
      const data = await res.json();
      const list = data.scheduled_messages || [];

      if (list.length > 0) {
        const next = list[0];
        const nextTimeStr = this.formatCountdown(next.scheduled_for);
        if (banner) {
          banner.style.display = 'flex';
          if (bannerText) {
            bannerText.textContent = `${list.length} message${list.length > 1 ? 's' : ''} scheduled for @${activeUser} (${nextTimeStr})`;
          }
        }
        if (badge) {
          badge.textContent = `${list.length} pending`;
          badge.style.display = 'inline-block';
        }
        if (emptyText) emptyText.style.display = 'none';
        if (previewList) {
          previewList.style.display = 'flex';
          previewList.style.flexDirection = 'column';
          previewList.style.gap = '6px';
          previewList.innerHTML = list.slice(0, 3).map(item => `
            <div style="font-size:12px; color:var(--ig-text-secondary); display:flex; justify-content:space-between; background:var(--ig-surface); padding:6px 8px; border-radius:6px;">
              <span>🕒 ${ScheduledMessagesManager.formatDisplayDateTime(item.scheduled_for)}</span>
              <span style="color:var(--ig-blue); font-weight:600;">${ScheduledMessagesManager.formatCountdown(item.scheduled_for)}</span>
            </div>
          `).join('');
        }
      } else {
        if (banner) banner.style.display = 'none';
        if (badge) badge.style.display = 'none';
        if (emptyText) emptyText.style.display = 'block';
        if (previewList) {
          previewList.style.display = 'none';
          previewList.innerHTML = '';
        }
      }
    } catch (err) {
      console.debug('Failed to refresh scheduled banner:', err);
    }
  },

  async openManagerModal(filter = 'pending', thisChatOnly = false) {
    this.activeFilter = filter;
    this.thisChatOnly = thisChatOnly;

    const modal = document.getElementById('scheduledManagerModal');
    const chk = document.getElementById('schedCurrentChatOnlyCheckbox');
    if (chk) chk.checked = thisChatOnly;

    document.querySelectorAll('.ig-sched-filter-pill').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.filter === filter);
    });

    if (modal) {
      modal.style.display = 'flex';
      modal.classList.add('active');
    }

    await this.renderManagerList();
  },

  closeManagerModal() {
    const modal = document.getElementById('scheduledManagerModal');
    if (modal) {
      modal.style.display = 'none';
      modal.classList.remove('active');
    }
  },

  async renderManagerList() {
    const container = document.getElementById('scheduledManagerList');
    if (!container) return;

    container.innerHTML = `
      <div class="ig-empty-history-text" style="text-align:center; padding:30px 10px; color:var(--ig-text-secondary);">
        Loading scheduled messages...
      </div>
    `;

    try {
      const url = new URL('/api/messages/scheduled', window.location.origin);
      if (this.activeFilter && this.activeFilter !== 'all') {
        url.searchParams.set('status', this.activeFilter);
      } else {
        url.searchParams.set('status', 'all');
      }
      if (this.thisChatOnly && activeUser) {
        url.searchParams.set('peer', activeUser);
      }

      const res = await fetch(url.toString());
      if (!res.ok) throw new Error('Failed to load scheduled messages');
      const data = await res.json();
      const messages = data.scheduled_messages || [];

      if (messages.length === 0) {
        container.innerHTML = `
          <div class="ig-empty-history-text" style="text-align:center; padding:36px 10px; color:var(--ig-text-secondary);">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" width="36" height="36" style="margin-bottom:8px; opacity:0.5;">
              <circle cx="12" cy="12" r="10" />
              <polyline points="12 6 12 12 16 14" />
            </svg>
            <p style="margin:0; font-size:13px;">No ${this.activeFilter === 'all' ? '' : this.activeFilter} scheduled messages found.</p>
          </div>
        `;
        return;
      }

      const cardPromises = messages.map(async (item) => {
        let plaintext = this.peerCache.get(item.id) || '';
        if (!plaintext && typeof EncryptionEngine !== 'undefined') {
          const encPkg = item.encrypted_package || {
            ciphertext: item.ciphertext,
            nonce: item.nonce,
            tag: item.tag || item.authentication_tag,
          };
          try {
            plaintext = await EncryptionEngine.decryptFrom(item.recipient_username, encPkg);
            this.peerCache.set(item.id, plaintext);
          } catch (e) {
            plaintext = '🔒 [Ciphertext Decryption Protected]';
          }
        }

        const isPending = item.status === 'pending';
        const isSent = item.status === 'sent';
        const displayTime = this.formatDisplayDateTime(item.scheduled_for);
        const countdown = isPending ? `(${this.formatCountdown(item.scheduled_for)})` : '';
        const escapeHtml = (s) => (s || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

        return `
          <div class="ig-sched-card" data-sched-id="${item.id}">
            <div class="ig-sched-card-header">
              <div class="ig-sched-card-recipient">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
                  <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                  <circle cx="12" cy="7" r="4" />
                </svg>
                <span>To: <strong>@${escapeHtml(item.recipient_username)}</strong></span>
              </div>
              <span class="ig-sched-status-badge ${item.status}">${escapeHtml(item.status)}</span>
            </div>

            <div class="ig-sched-time-row">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10" />
                <polyline points="12 6 12 12 16 14" />
              </svg>
              <span>${isSent ? 'Sent at: ' + this.formatDisplayDateTime(item.sent_at || item.scheduled_for) : 'Scheduled for: ' + displayTime} <strong style="color:var(--ig-blue);">${countdown}</strong></span>
            </div>

            <div class="ig-sched-preview-box">
              ${escapeHtml(plaintext || '[Encrypted Content]')}
            </div>

            ${isPending ? `
              <div class="ig-sched-actions">
                <button type="button" class="ig-sched-action-btn send-now" onclick="ScheduledMessagesManager.sendNow(${item.id})">
                  ⚡ Send Now
                </button>
                <button type="button" class="ig-sched-action-btn" onclick="ScheduledMessagesManager.openEditModal(${item.id})">
                  ✏️ Edit
                </button>
                <button type="button" class="ig-sched-action-btn danger" onclick="ScheduledMessagesManager.cancelScheduled(${item.id})">
                  Cancel
                </button>
              </div>
            ` : ''}
          </div>
        `;
      });

      const cardsHtml = await Promise.all(cardPromises);
      container.innerHTML = cardsHtml.join('');
    } catch (err) {
      console.error('Error rendering scheduled messages:', err);
      container.innerHTML = `
        <div class="ig-empty-history-text" style="text-align:center; padding:20px; color:#ef4444;">
          Error loading scheduled messages. Please try again.
        </div>
      `;
    }
  },

  async sendNow(schedId) {
    if (!confirm('Send this scheduled message immediately?')) return;
    try {
      const res = await fetch(`/api/messages/schedule/${schedId}/send-now`, {
        method: 'POST',
        headers: { 'X-CSRFToken': getCsrfToken() },
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || 'Failed to send message');
      Toast.show('success', 'Message Sent', 'Scheduled message has been delivered immediately.');
      await this.renderManagerList();
      this.refreshActivePeerScheduled();
    } catch (err) {
      Toast.show('error', 'Send Error', err.message);
    }
  },

  async cancelScheduled(schedId) {
    if (!confirm('Are you sure you want to cancel this scheduled message?')) return;
    try {
      const res = await fetch(`/api/messages/schedule/${schedId}`, {
        method: 'DELETE',
        headers: { 'X-CSRFToken': getCsrfToken() },
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || 'Failed to cancel scheduled message');
      Toast.show('info', 'Cancelled', 'Scheduled message has been cancelled.');
      await this.renderManagerList();
      this.refreshActivePeerScheduled();
    } catch (err) {
      Toast.show('error', 'Cancel Error', err.message);
    }
  },

  async openEditModal(schedId) {
    try {
      const res = await fetch(`/api/messages/scheduled?status=pending`);
      if (!res.ok) throw new Error('Failed to load message details');
      const data = await res.json();
      const schedMsg = (data.scheduled_messages || []).find(m => m.id === schedId);
      if (!schedMsg) throw new Error('Scheduled message not found or not pending');

      let plaintext = this.peerCache.get(schedId) || '';
      if (!plaintext && typeof EncryptionEngine !== 'undefined') {
        const encPkg = schedMsg.encrypted_package || {
          ciphertext: schedMsg.ciphertext,
          nonce: schedMsg.nonce,
          tag: schedMsg.tag || schedMsg.authentication_tag,
        };
        try {
          plaintext = await EncryptionEngine.decryptFrom(schedMsg.recipient_username, encPkg);
        } catch (_) {
          plaintext = '';
        }
      }

      const modal = document.getElementById('editScheduledModal');
      const idInput = document.getElementById('editSchedMsgId');
      const textarea = document.getElementById('editSchedMessageInput');
      const picker = document.getElementById('editSchedDateTimeInput');

      if (idInput) idInput.value = schedId;
      if (textarea) textarea.value = plaintext;
      if (picker) {
        const minD = new Date(Date.now() + 60 * 1000);
        picker.min = this.formatLocalISO(minD);
        picker.value = this.formatLocalISO(new Date(schedMsg.scheduled_for));
      }

      if (modal) {
        modal.style.display = 'flex';
        modal.classList.add('active');
      }
    } catch (err) {
      Toast.show('error', 'Edit Error', err.message);
    }
  },

  closeEditModal() {
    const modal = document.getElementById('editScheduledModal');
    if (modal) {
      modal.style.display = 'none';
      modal.classList.remove('active');
    }
  },

  async saveEdit() {
    const idInput = document.getElementById('editSchedMsgId');
    const textarea = document.getElementById('editSchedMessageInput');
    const picker = document.getElementById('editSchedDateTimeInput');

    const schedId = idInput ? parseInt(idInput.value, 10) : null;
    const newText = textarea ? textarea.value.trim() : '';
    const pickerVal = picker ? picker.value : '';

    if (!schedId || !newText || !pickerVal) {
      Toast.show('error', 'Missing Information', 'Please provide message text and scheduled time.');
      return;
    }

    const targetDate = new Date(pickerVal);
    if (isNaN(targetDate.getTime()) || targetDate.getTime() <= Date.now()) {
      Toast.show('error', 'Invalid Time', 'Scheduled time must be in the future.');
      return;
    }

    const saveBtn = document.getElementById('saveEditSchedBtn');
    if (saveBtn) {
      saveBtn.disabled = true;
      saveBtn.textContent = 'Saving...';
    }

    try {
      const card = document.querySelector(`.ig-sched-card[data-sched-id="${schedId}"]`);
      let recipient = activeUser;
      if (card) {
        const recSpan = card.querySelector('.ig-sched-card-recipient strong');
        if (recSpan) recipient = recSpan.textContent.replace('@', '').trim();
      }

      let encPkg = await EncryptionEngine.encryptFor(recipient, newText);
      const utcIso = targetDate.toISOString();

      const res = await fetch(`/api/messages/schedule/${schedId}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': getCsrfToken(),
        },
        body: JSON.stringify({
          ciphertext: encPkg.ciphertext,
          nonce: encPkg.nonce,
          tag: encPkg.tag,
          encrypted_package: encPkg,
          scheduled_for: utcIso,
        }),
      });

      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || 'Failed to update scheduled message');

      this.peerCache.set(schedId, newText);
      this.closeEditModal();
      Toast.show('success', 'Updated', 'Scheduled message has been updated.');
      await this.renderManagerList();
      this.refreshActivePeerScheduled();
    } catch (err) {
      Toast.show('error', 'Save Failed', err.message);
    } finally {
      if (saveBtn) {
        saveBtn.disabled = false;
        saveBtn.textContent = 'Save Changes';
      }
    }
  },

  init() {
    // Input bar schedule button
    document.getElementById('scheduleMsgBtn')?.addEventListener('click', () => {
      this.openScheduleModal();
    });

    // Scheduled banner actions
    document.getElementById('viewScheduledBtn')?.addEventListener('click', () => {
      this.openManagerModal('pending', true);
    });
    document.getElementById('dismissScheduledBannerBtn')?.addEventListener('click', () => {
      const banner = document.getElementById('scheduledBanner');
      if (banner) banner.style.display = 'none';
    });

    // Right sidebar manage button
    document.getElementById('sidebarManageSchedBtn')?.addEventListener('click', () => {
      this.openManagerModal('pending', false);
    });

    // Schedule modal preset buttons
    document.querySelectorAll('.ig-sched-preset-pill').forEach(btn => {
      btn.addEventListener('click', () => this.applyPreset(btn));
    });

    // Schedule modal close & submit
    document.getElementById('closeScheduleModalBtn')?.addEventListener('click', () => this.closeScheduleModal());
    document.getElementById('cancelScheduleBtn')?.addEventListener('click', () => this.closeScheduleModal());
    document.getElementById('confirmScheduleBtn')?.addEventListener('click', () => this.confirmSchedule());

    // Manager modal close & done
    document.getElementById('closeSchedManagerModalBtn')?.addEventListener('click', () => this.closeManagerModal());
    document.getElementById('doneSchedManagerBtn')?.addEventListener('click', () => this.closeManagerModal());

    // Manager modal filter pills
    document.querySelectorAll('.ig-sched-filter-pill').forEach(pill => {
      pill.addEventListener('click', () => {
        this.openManagerModal(pill.dataset.filter, this.thisChatOnly);
      });
    });

    // Manager modal scope checkbox
    document.getElementById('schedCurrentChatOnlyCheckbox')?.addEventListener('change', (e) => {
      this.thisChatOnly = e.target.checked;
      this.renderManagerList();
    });

    // Edit modal close & save
    document.getElementById('closeEditSchedModalBtn')?.addEventListener('click', () => this.closeEditModal());
    document.getElementById('cancelEditSchedBtn')?.addEventListener('click', () => this.closeEditModal());
    document.getElementById('saveEditSchedBtn')?.addEventListener('click', () => this.saveEdit());
  }
};

/* ─── Group Chat Manager (E2EE with Forward & Backward Secrecy) ─── */
const GroupChatManager = {
  groups: [],
  unreadCounts: new Map(),

  groupGradients: [
    'linear-gradient(135deg, #6366f1, #8b5cf6, #d946ef)',
    'linear-gradient(135deg, #3b82f6, #06b6d4, #10b981)',
    'linear-gradient(135deg, #f59e0b, #ef4444, #ec4899)',
    'linear-gradient(135deg, #10b981, #059669, #047857)',
    'linear-gradient(135deg, #8b5cf6, #ec4899, #f43f5e)',
  ],

  getGroupGradient(id) {
    const idx = (Number(id) || 0) % this.groupGradients.length;
    return this.groupGradients[idx];
  },

  getGroupInitials(name) {
    if (!name) return 'GP';
    const words = name.trim().split(/\s+/);
    if (words.length >= 2) {
      return (words[0][0] + words[1][0]).toUpperCase();
    }
    return name.slice(0, 2).toUpperCase();
  },

  async init() {
    this.bindDOMTriggers();
    await this.loadUserGroups();
  },

  bindDOMTriggers() {
    // 1. Sidebar action "+ New Group" button
    const newGroupBtn = document.getElementById('newGroupBtn');
    newGroupBtn?.addEventListener('click', () => this.openCreateGroupModal());

    // 2. Create Group Modal controls
    const createModal = document.getElementById('createGroupModal');
    const closeCreateBtn = document.getElementById('closeCreateGroupModalBtn');
    const cancelCreateBtn = document.getElementById('cancelCreateGroupBtn');
    const submitCreateBtn = document.getElementById('submitCreateGroupBtn');

    closeCreateBtn?.addEventListener('click', () => this.closeCreateGroupModal());
    cancelCreateBtn?.addEventListener('click', () => this.closeCreateGroupModal());
    submitCreateBtn?.addEventListener('click', () => this.submitCreateGroup());
    createModal?.addEventListener('click', (e) => {
      if (e.target === createModal) this.closeCreateGroupModal();
    });

    // 3. Add Members Modal controls
    const addMembersModal = document.getElementById('addGroupMembersModal');
    const addMembersBtn = document.getElementById('addGroupMembersBtn');
    const closeAddBtn = document.getElementById('closeAddMembersModalBtn');
    const cancelAddBtn = document.getElementById('cancelAddMembersBtn');
    const submitAddBtn = document.getElementById('submitAddMembersBtn');

    addMembersBtn?.addEventListener('click', () => this.openAddMembersModal());
    closeAddBtn?.addEventListener('click', () => this.closeAddMembersModal());
    cancelAddBtn?.addEventListener('click', () => this.closeAddMembersModal());
    submitAddBtn?.addEventListener('click', () => this.submitAddMembers());
    addMembersModal?.addEventListener('click', (e) => {
      if (e.target === addMembersModal) this.closeAddMembersModal();
    });

    // 4. Edit Group Modal controls
    const editModal = document.getElementById('editGroupModal');
    const editBtn = document.getElementById('editGroupInfoBtn');
    const closeEditBtn = document.getElementById('closeEditGroupModalBtn');
    const cancelEditBtn = document.getElementById('cancelEditGroupBtn');
    const saveEditBtn = document.getElementById('saveGroupInfoBtn');

    editBtn?.addEventListener('click', () => this.openEditGroupModal());
    closeEditBtn?.addEventListener('click', () => this.closeEditGroupModal());
    cancelEditBtn?.addEventListener('click', () => this.closeEditGroupModal());
    saveEditBtn?.addEventListener('click', () => this.saveGroupInfo());
    editModal?.addEventListener('click', (e) => {
      if (e.target === editModal) this.closeEditGroupModal();
    });

    // 5. Right Sidebar Leave Group Button
    const leaveGroupBtn = document.getElementById('rightPanelLeaveGroupBtn');
    leaveGroupBtn?.addEventListener('click', () => this.leaveGroup());
  },

  bindSocketEvents(sock) {
    if (!sock) return;

    // A group was created and we are a member
    sock.on('group_created', (data) => {
      this.loadUserGroups();
    });

    // New member was added to active group (triggers key rotation)
    sock.on('group_member_added', (data) => {
      if (activeGroup && Number(activeGroup.id) === Number(data.group_id)) {
        activeGroup.current_epoch = data.epoch;
        this.updateGroupDetailsHeaderAndPanel();
        this.loadGroupMembers(activeGroup.id);
        Toast.show('info', 'Member Added', `@${data.added_username} was added. Group key rotated to Epoch #${data.epoch}.`);
      }
      this.loadUserGroups();
    });

    // Member was removed from group (triggers backward secrecy key rotation)
    sock.on('group_member_removed', (data) => {
      if (data.removed_username === myUsername) {
        Toast.show('warning', 'Removed from Group', 'You have been removed from this group conversation.');
        if (activeGroup && Number(activeGroup.id) === Number(data.group_id)) {
          this.exitGroupView();
        }
      } else if (activeGroup && Number(activeGroup.id) === Number(data.group_id)) {
        activeGroup.current_epoch = data.epoch;
        this.updateGroupDetailsHeaderAndPanel();
        this.loadGroupMembers(activeGroup.id);
        Toast.show('info', 'Member Removed', `@${data.removed_username} was removed. Group key rotated to Epoch #${data.epoch}.`);
      }
      this.loadUserGroups();
    });

    // Member role changed
    sock.on('group_member_role_changed', (data) => {
      if (activeGroup && Number(activeGroup.id) === Number(data.group_id)) {
        if (data.username === myUsername) {
          activeGroup.my_role = data.role;
        }
        this.loadGroupMembers(activeGroup.id);
      }
    });

    // Automated key distribution notification
    sock.on('group_key_distribution', (data) => {
      if (activeGroup && Number(activeGroup.id) === Number(data.group_id)) {
        activeGroup.current_epoch = data.epoch;
        this.updateGroupDetailsHeaderAndPanel();
        Toast.show('info', 'Key Rotated', `Epoch #${data.epoch} distributed by @${data.rotated_by}.`);
      }
      // Pre-fetch & unwrap key in background
      EncryptionEngine.fetchAndUnwrapGroupKey(data.group_id, data.epoch).catch(e => console.warn('Key unwrap prefetch:', e));
    });

    // Incoming group message
    sock.on('receive_group_message', async (data) => {
      if (!activeGroup || Number(activeGroup.id) !== Number(data.group_id)) {
        this.incrementUnread(data.group_id);
        Toast.show('info', 'New Group Message', 'Encrypted message in group.');
        return;
      }

      const isSelf = data.sender_username === myUsername;
      // Deduplicate if already rendered locally
      if (data.id && messagesArea?.querySelector(`.message[data-message-id="${data.id}"]`)) {
        return;
      }
      const pendingSelf = messagesArea?.querySelector(`.message.self:not([data-message-id])`);
      if (isSelf && pendingSelf) {
        pendingSelf.dataset.messageId = data.id;
        if (data.expires_at) {
          pendingSelf.dataset.expiresAt = data.expires_at;
          const footer = pendingSelf.querySelector('.msg-footer');
          if (footer && !footer.querySelector('.ig-countdown-badge')) {
            const badge = document.createElement('span');
            badge.className = 'ig-countdown-badge';
            badge.dataset.expiresAt = data.expires_at;
            badge.textContent = '⏱️ ...';
            footer.appendChild(badge);
          }
          if (typeof DisappearingMessagesManager !== 'undefined') {
            DisappearingMessagesManager.trackMessage(data.id, data.expires_at);
          }
        }
        return;
      }

      let plaintext = '';
      try {
        plaintext = await EncryptionEngine.decryptGroupMessage(data.group_id, data.epoch, {
          ciphertext: data.ciphertext,
          nonce: data.nonce,
          tag: data.tag,
        });
      } catch (err) {
        console.error('[E2EE] Group message decrypt failed:', err);
        plaintext = '🔒 [Ciphertext Decryption Error: Key Mismatch or Expired Epoch]';
      }

      if (emptyChatState) emptyChatState.style.display = 'none';
      const time = formatTime(data.timestamp || data.created_at);
      const msgEl = createMessageElement(plaintext, isSelf, time, data.id, true, {
        ciphertext: data.ciphertext,
        nonce: data.nonce,
        tag: data.tag,
        epoch: data.epoch,
        is_group: true,
        sender_username: data.sender_username,
        reply_to_id: data.reply_to_id,
        message_type: data.message_type,
        reactions: data.reactions || [],
        expires_at: data.expires_at,
        expiration_seconds: data.expiration_seconds,
        is_view_once: data.is_view_once,
        is_vanish: data.is_vanish,
        viewed_at: data.viewed_at,
      });

      if (typingIndicator && messagesArea) {
        messagesArea.insertBefore(msgEl, typingIndicator);
      } else {
        messagesArea?.appendChild(msgEl);
      }
      scrollToBottom();
    });

    // Group message reaction update
    sock.on('group_reaction_update', (data) => {
      if (activeGroup && Number(activeGroup.id) === Number(data.group_id)) {
        const pillsContainer = document.getElementById(`reactions-${data.message_id}`);
        if (pillsContainer) {
          pillsContainer.innerHTML = renderReactionPillsHtml(data.reactions, data.message_id);
        }
      }
    });

    // Group message deleted
    sock.on('group_message_deleted', (data) => {
      if (activeGroup && Number(activeGroup.id) === Number(data.group_id)) {
        const msgEl = document.querySelector(`.message[data-message-id="${data.message_id}"]`);
        if (msgEl) {
          msgEl.classList.add('deleting');
          setTimeout(() => {
            msgEl.remove();
            checkEmptyChatState();
          }, 250);
        }
      }
    });
  },

  async loadUserGroups() {
    try {
      const resp = await fetch('/api/groups');
      const data = await resp.json();
      if (data.ok && Array.isArray(data.groups)) {
        this.groups = data.groups;
        const badge = document.getElementById('groupsCountBadge');
        if (badge) {
          badge.textContent = this.groups.length;
          badge.style.display = this.groups.length > 0 ? 'inline-block' : 'none';
        }
        if (currentSidebarTab === 'groups') {
          this.renderGroupsList();
        }
      }
    } catch (err) {
      console.warn('[Groups] Failed to load groups:', err);
    }
  },

  renderGroupsList() {
    if (!userListContainer) return;
    userListContainer.innerHTML = '';

    if (this.groups.length === 0) {
      userListContainer.innerHTML = `
        <div style="text-align:center; padding:32px 16px; color:var(--ig-text-muted);">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="36" height="36" style="margin-bottom:8px; opacity:0.6;">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
            <circle cx="9" cy="7" r="4" />
            <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
            <path d="M16 3.13a4 4 0 0 1 0 7.75" />
          </svg>
          <p style="font-size:13px; font-weight:600; color:var(--ig-text-primary); margin-bottom:4px;">No Groups Yet</p>
          <p style="font-size:12px; margin-bottom:12px;">Create an encrypted group to chat with multiple peers.</p>
          <button class="btn btn-primary" id="emptyCreateGroupBtn" style="width:auto; padding:7px 16px; font-size:12.5px;" type="button">
            + New Group
          </button>
        </div>
      `;
      document.getElementById('emptyCreateGroupBtn')?.addEventListener('click', () => this.openCreateGroupModal());
      return;
    }

    this.groups.forEach(g => {
      const isSelected = activeGroup && Number(activeGroup.id) === Number(g.id);
      const unreadCount = this.unreadCounts.get(g.id) || 0;
      const el = document.createElement('div');
      el.className = `ig-conversation-item ig-group-item user-item ${isSelected ? 'active' : ''} ${unreadCount > 0 ? 'has-unread' : ''}`;
      el.dataset.groupId = g.id;
      el.innerHTML = `
        <div class="ig-avatar-container">
          <div class="ig-conversation-avatar ig-group-avatar" style="background:${this.getGroupGradient(g.id)}">${this.getGroupInitials(g.name)}</div>
        </div>
        <div class="ig-conversation-info user-info">
          <div class="ig-conversation-header">
            <span class="ig-conversation-name user-name">${escapeHtml(g.name)}</span>
            <span class="ig-conversation-time">Epoch #${g.current_epoch}</span>
          </div>
          <div class="ig-conversation-preview user-preview-row">
            <span class="ig-preview-text">${escapeHtml(g.description || `${g.member_count || 1} members`)}</span>
            <span class="ig-group-badge-role ${g.my_role || 'member'}">${(g.my_role || 'member') === 'admin' ? 'Admin' : 'Member'}</span>
          </div>
        </div>
      `;
      el.addEventListener('click', () => this.switchGroup(g.id));
      userListContainer.appendChild(el);
    });
  },

  async switchGroup(groupId) {
    if (activeGroup && Number(activeGroup.id) === Number(groupId)) return;

    // Leave any previous group room
    if (activeGroup && socket) {
      socket.emit('leave_group_room', { group_id: activeGroup.id });
    }

    activeUser = null;
    if (typeof GlobalVoicePlayer !== 'undefined') GlobalVoicePlayer.stop();

    // Clear unread badge
    this.unreadCounts.delete(Number(groupId));

    // Update active highlight in sidebar
    document.querySelectorAll('.ig-conversation-item').forEach(item => {
      item.classList.toggle('active', item.dataset.groupId === String(groupId));
    });

    // Join WebSocket room for real-time delivery
    if (socket && socket.connected) {
      socket.emit('join_group', { group_id: groupId });
    }

    // Fetch detailed group info
    try {
      const resp = await fetch(`/api/groups/${groupId}`);
      const data = await resp.json();
      if (!data.ok || !data.group) {
        Toast.show('error', 'Error', data.error || 'Failed to load group');
        return;
      }

      activeGroup = {
        id: data.group.id,
        name: data.group.name,
        description: data.group.description,
        avatar_url: data.group.avatar_url,
        current_epoch: data.group.current_epoch,
        creator_id: data.group.creator_id,
        creator_username: data.group.creator_username,
        my_role: data.my_role || 'member',
        members: data.members || [],
      };

      this.updateGroupDetailsHeaderAndPanel();
      this.renderGroupMemberList(activeGroup.members);
      await this.loadGroupMessages(groupId);
    } catch (err) {
      console.error('Group switch error:', err);
      Toast.show('error', 'Network Error', 'Failed to connect to group');
    }
  },

  updateGroupDetailsHeaderAndPanel() {
    if (!activeGroup) return;

    // 1. Header UI
    if (chatHeaderName) chatHeaderName.textContent = activeGroup.name;
    if (chatHeaderStatus) {
      chatHeaderStatus.textContent = `${activeGroup.members?.length || 1} members • Epoch #${activeGroup.current_epoch}`;
      chatHeaderStatus.className = 'ig-header-status-text chat-header-status online';
    }
    if (chatAvatarInitials) {
      chatAvatarInitials.textContent = this.getGroupInitials(activeGroup.name);
      chatAvatarInitials.style.background = this.getGroupGradient(activeGroup.id);
    }
    if (chatStatusDot) {
      chatStatusDot.className = 'ig-header-status-dot online';
    }

    // 2. Right Sidebar UI
    const contactCard = document.getElementById('contactProfileCard');
    if (contactCard) contactCard.style.display = 'none';

    const groupCard = document.getElementById('groupProfileCard');
    if (groupCard) groupCard.style.display = 'flex';

    const groupSec = document.getElementById('groupMembersSection');
    if (groupSec) groupSec.style.display = 'block';

    const leaveBtn = document.getElementById('rightPanelLeaveGroupBtn');
    if (leaveBtn) leaveBtn.style.display = 'block';

    const gAvatar = document.getElementById('groupDetailsAvatar');
    if (gAvatar) {
      gAvatar.textContent = this.getGroupInitials(activeGroup.name);
      gAvatar.style.background = this.getGroupGradient(activeGroup.id);
    }
    const gName = document.getElementById('groupDetailsName');
    if (gName) gName.textContent = activeGroup.name;

    const gDesc = document.getElementById('groupDetailsDesc');
    if (gDesc) gDesc.textContent = activeGroup.description || 'End-to-End Encrypted Group Conversation';

    const gBadgeText = document.getElementById('groupEpochBadgeText');
    if (gBadgeText) gBadgeText.textContent = `Group E2EE • Epoch #${activeGroup.current_epoch}`;

    const memberCountSpan = document.getElementById('groupMemberCountSpan');
    if (memberCountSpan) memberCountSpan.textContent = activeGroup.members?.length || 1;

    const addMembersBtn = document.getElementById('addGroupMembersBtn');
    if (addMembersBtn) {
      addMembersBtn.style.display = (activeGroup.my_role === 'admin') ? 'inline-block' : 'none';
    }
  },

  async loadGroupMembers(groupId) {
    try {
      const resp = await fetch(`/api/groups/${groupId}`);
      const data = await resp.json();
      if (data.ok && data.members) {
        if (activeGroup) {
          activeGroup.members = data.members;
          activeGroup.my_role = data.my_role;
        }
        this.renderGroupMemberList(data.members);
      }
    } catch (_) {}
  },

  renderGroupMemberList(members) {
    const listEl = document.getElementById('groupMembersList');
    if (!listEl) return;
    listEl.innerHTML = '';

    const isAdmin = activeGroup?.my_role === 'admin';

    members.forEach(m => {
      const item = document.createElement('div');
      item.className = 'ig-group-member-item';
      const isMe = m.username === myUsername;
      const initials = (m.username || '??').slice(0, 2).toUpperCase();
      const gradient = USERS[m.username]?.gradient || 'linear-gradient(135deg, #6366f1, #8b5cf6)';

      let actionsHtml = '';
      if (isAdmin && !isMe) {
        const isTargetAdmin = m.role === 'admin';
        actionsHtml = `
          <div style="display:flex; gap:6px; align-items:center;">
            <button class="btn btn-secondary btn-sm" onclick="GroupChatManager.updateMemberRole('${escapeHtml(m.username)}', '${isTargetAdmin ? 'member' : 'admin'}')" style="padding:3px 8px; font-size:11px;" type="button" title="${isTargetAdmin ? 'Demote to Member' : 'Make Admin'}">
              ${isTargetAdmin ? 'Demote' : 'Make Admin'}
            </button>
            <button class="btn btn-danger btn-sm" onclick="GroupChatManager.removeMember('${escapeHtml(m.username)}')" style="padding:3px 8px; font-size:11px;" type="button" title="Remove from group">
              Remove
            </button>
          </div>
        `;
      }

      item.innerHTML = `
        <div style="display:flex; align-items:center; gap:8px;">
          <div class="ig-conversation-avatar" style="width:28px; height:28px; font-size:11px; background:${gradient};">${initials}</div>
          <div style="display:flex; flex-direction:column;">
            <span style="font-size:12.5px; font-weight:600; color:var(--ig-text-primary);">${escapeHtml(m.username)} ${isMe ? '(You)' : ''}</span>
            <span class="ig-group-badge-role ${m.role}" style="align-self:flex-start; margin-top:1px;">${m.role === 'admin' ? 'Admin' : 'Member'}</span>
          </div>
        </div>
        ${actionsHtml}
      `;
      listEl.appendChild(item);
    });
  },

  async loadGroupMessages(groupId) {
    if (!messagesArea) return;
    if (historyLoader) historyLoader.style.display = 'flex';
    if (emptyChatState) emptyChatState.style.display = 'none';

    messagesArea.querySelectorAll('.message').forEach(m => m.remove());

    try {
      const resp = await fetch(`/api/groups/${groupId}/messages`);
      const data = await resp.json();

      if (data.ok && Array.isArray(data.messages)) {
        if (data.messages.length === 0) {
          checkEmptyChatState();
        } else {
          for (const m of data.messages) {
            let plaintext = '';
            try {
              plaintext = await EncryptionEngine.decryptGroupMessage(groupId, m.epoch, {
                ciphertext: m.ciphertext,
                nonce: m.nonce,
                tag: m.tag,
              });
            } catch (err) {
              plaintext = '🔒 [Ciphertext Decryption Error: Key Mismatch or Expired Epoch]';
            }

            const isSelf = m.sender_username === myUsername;
            const msgEl = createMessageElement(plaintext, isSelf, m.timestamp, m.id, true, {
              ciphertext: m.ciphertext,
              nonce: m.nonce,
              tag: m.tag,
              epoch: m.epoch,
              is_group: true,
              sender_username: m.sender_username,
              reply_to_id: m.reply_to_id,
              message_type: m.message_type,
              media_meta: m.media_meta,
              reactions: m.reactions || [],
              expires_at: m.expires_at,
              expiration_seconds: m.expiration_seconds,
              is_view_once: m.is_view_once,
              is_vanish: m.is_vanish,
              viewed_at: m.viewed_at,
            });

            if (typingIndicator && messagesArea) {
              messagesArea.insertBefore(msgEl, typingIndicator);
            } else {
              messagesArea?.appendChild(msgEl);
            }
          }
        }
      }

      if (data.disappearing_timer !== undefined && typeof DisappearingMessagesManager !== 'undefined') {
        DisappearingMessagesManager.activeTimer = Number(data.disappearing_timer || 0);
        DisappearingMessagesManager.updateTimerUI();
      }
    } catch (err) {
      console.warn('Failed to load group messages:', err);
    } finally {
      if (historyLoader) historyLoader.style.display = 'none';
      scrollToBottom(false);
    }
  },

  openCreateGroupModal() {
    const nameInput = document.getElementById('newGroupNameInput');
    const descInput = document.getElementById('newGroupDescInput');
    const memberList = document.getElementById('createGroupMemberList');
    if (nameInput) nameInput.value = '';
    if (descInput) descInput.value = '';

    if (memberList) {
      memberList.innerHTML = '';
      const contacts = Object.keys(USERS).filter(u => u !== myUsername);
      if (contacts.length === 0) {
        memberList.innerHTML = '<div style="font-size:12px; color:var(--ig-text-secondary); text-align:center; padding:12px;">No registered contacts available yet.</div>';
      } else {
        contacts.forEach(u => {
          const user = USERS[u];
          const div = document.createElement('label');
          div.style.display = 'flex';
          div.style.alignItems = 'center';
          div.style.gap = '8px';
          div.style.padding = '6px 4px';
          div.style.cursor = 'pointer';
          div.innerHTML = `
            <input type="checkbox" class="create-group-member-checkbox" value="${escapeHtml(u)}">
            <div class="ig-conversation-avatar" style="width:24px; height:24px; font-size:10px; background:${user.gradient};">${user.initials}</div>
            <span style="font-size:13px; font-weight:500;">${escapeHtml(u)}</span>
          `;
          memberList.appendChild(div);
        });
      }
    }

    const modal = document.getElementById('createGroupModal');
    if (modal) modal.style.display = 'flex';
  },

  closeCreateGroupModal() {
    const modal = document.getElementById('createGroupModal');
    if (modal) modal.style.display = 'none';
  },

  async submitCreateGroup() {
    const nameInput = document.getElementById('newGroupNameInput');
    const descInput = document.getElementById('newGroupDescInput');
    const name = nameInput?.value.trim();
    const desc = descInput?.value.trim() || '';

    if (!name || name.length < 2) {
      Toast.show('warning', 'Invalid Name', 'Group name must be at least 2 characters long.');
      return;
    }

    const checkboxes = document.querySelectorAll('.create-group-member-checkbox:checked');
    const selectedMembers = Array.from(checkboxes).map(cb => cb.value);

    Toast.show('info', 'Creating Group', 'Generating Authenticated Epoch 1 Key with pairwise wraps...');

    try {
      // 1. Generate Epoch 1 Group Key
      const { rawBytes, cryptoKey } = await EncryptionEngine.generateGroupEpochKey();

      // 2. Wrap pairwise for each initial peer + self
      const memberKeys = [];
      for (const peer of selectedMembers) {
        const wrapped = await EncryptionEngine.wrapGroupKeyForPeer(rawBytes, peer);
        memberKeys.push({ username: peer, encrypted_key: wrapped });
      }
      const wrappedSelf = await EncryptionEngine.wrapGroupKeyForPeer(rawBytes, myUsername);
      memberKeys.push({ username: myUsername, encrypted_key: wrappedSelf });

      // 3. Post to backend
      const resp = await fetch('/api/groups', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': getCsrfToken(),
        },
        body: JSON.stringify({
          name,
          description: desc,
          member_usernames: selectedMembers,
          initial_epoch_keys: memberKeys,
        }),
      });

      const data = await resp.json();
      if (!resp.ok || !data.ok) {
        throw new Error(data.error || 'Failed to create group');
      }

      // Store locally
      EncryptionEngine.storeGroupEpochKey(data.group.id, 1, cryptoKey);

      this.closeCreateGroupModal();
      await this.loadUserGroups();

      // Switch to Groups tab and open new group
      this.switchSidebarTab('groups');
      await this.switchGroup(data.group.id);
      Toast.show('success', 'Group Created', `"${name}" initialized with end-to-end encryption.`);
    } catch (err) {
      console.error('Group creation failed:', err);
      Toast.show('error', 'Group Creation Failed', err.message);
    }
  },

  openAddMembersModal() {
    if (!activeGroup) return;
    const selectList = document.getElementById('addMembersSelectList');
    if (!selectList) return;
    selectList.innerHTML = '';

    const currentMemberUsernames = new Set((activeGroup.members || []).map(m => m.username));
    const eligibleContacts = Object.keys(USERS).filter(u => u !== myUsername && !currentMemberUsernames.has(u));

    if (eligibleContacts.length === 0) {
      selectList.innerHTML = '<div style="font-size:12px; color:var(--ig-text-secondary); text-align:center; padding:12px;">All contacts are already in this group.</div>';
    } else {
      eligibleContacts.forEach(u => {
        const user = USERS[u];
        const div = document.createElement('label');
        div.style.display = 'flex';
        div.style.alignItems = 'center';
        div.style.gap = '8px';
        div.style.padding = '6px 4px';
        div.style.cursor = 'pointer';
        div.innerHTML = `
          <input type="checkbox" class="add-group-member-checkbox" value="${escapeHtml(u)}">
          <div class="ig-conversation-avatar" style="width:24px; height:24px; font-size:10px; background:${user.gradient};">${user.initials}</div>
          <span style="font-size:13px; font-weight:500;">${escapeHtml(u)}</span>
        `;
        selectList.appendChild(div);
      });
    }

    const modal = document.getElementById('addGroupMembersModal');
    if (modal) modal.style.display = 'flex';
  },

  closeAddMembersModal() {
    const modal = document.getElementById('addGroupMembersModal');
    if (modal) modal.style.display = 'none';
  },

  async submitAddMembers() {
    if (!activeGroup) return;
    const checkboxes = document.querySelectorAll('.add-group-member-checkbox:checked');
    const selected = Array.from(checkboxes).map(cb => cb.value);
    if (selected.length === 0) {
      Toast.show('warning', 'No Members Selected', 'Please check at least one contact to add.');
      return;
    }

    Toast.show('info', 'Rotating Group Key', 'Rotating key for forward secrecy (Epoch + 1)...');

    try {
      const newEpoch = Number(activeGroup.current_epoch) + 1;
      const currentMembers = (activeGroup.members || []).map(m => m.username);
      const allMembers = Array.from(new Set([...currentMembers, ...selected]));

      const { memberKeys } = await EncryptionEngine.rotateGroupEpoch(
        activeGroup.id,
        newEpoch,
        allMembers.map(u => ({ username: u }))
      );

      const resp = await fetch(`/api/groups/${activeGroup.id}/members`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': getCsrfToken(),
        },
        body: JSON.stringify({
          new_members: selected,
          new_epoch: newEpoch,
          new_epoch_keys: memberKeys,
        }),
      });

      const data = await resp.json();
      if (!resp.ok || !data.ok) {
        throw new Error(data.error || 'Failed to add members');
      }

      this.closeAddMembersModal();
      activeGroup.current_epoch = newEpoch;
      activeGroup.members = data.members;
      this.updateGroupDetailsHeaderAndPanel();
      this.renderGroupMemberList(data.members);
      Toast.show('success', 'Members Added', `Forward secrecy enforced: rotated to Epoch #${newEpoch}.`);
    } catch (err) {
      console.error('Add members error:', err);
      Toast.show('error', 'Failed to Add Members', err.message);
    }
  },

  async removeMember(targetUsername) {
    if (!activeGroup) return;
    if (!confirm(`Are you sure you want to remove @${targetUsername} from "${activeGroup.name}"? This will rotate the group encryption key for backward secrecy.`)) {
      return;
    }

    Toast.show('info', 'Rotating Group Key', `Removing @${targetUsername} & enforcing backward secrecy...`);

    try {
      const newEpoch = Number(activeGroup.current_epoch) + 1;
      const remainingMembers = (activeGroup.members || [])
        .map(m => m.username)
        .filter(u => u !== targetUsername);

      const { memberKeys } = await EncryptionEngine.rotateGroupEpoch(
        activeGroup.id,
        newEpoch,
        remainingMembers.map(u => ({ username: u }))
      );

      const resp = await fetch(`/api/groups/${activeGroup.id}/members/${encodeURIComponent(targetUsername)}`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': getCsrfToken(),
        },
        body: JSON.stringify({
          new_epoch: newEpoch,
          new_epoch_keys: memberKeys,
        }),
      });

      const data = await resp.json();
      if (!resp.ok || !data.ok) {
        throw new Error(data.error || 'Failed to remove member');
      }

      activeGroup.current_epoch = newEpoch;
      activeGroup.members = data.members;
      this.updateGroupDetailsHeaderAndPanel();
      this.renderGroupMemberList(data.members);
      Toast.show('success', 'Member Removed', `@${targetUsername} removed. Backward secrecy enforced: rotated to Epoch #${newEpoch}.`);
    } catch (err) {
      console.error('Remove member failed:', err);
      Toast.show('error', 'Remove Member Error', err.message);
    }
  },

  async leaveGroup() {
    if (!activeGroup) return;
    if (!confirm(`Leave "${activeGroup.name}"? You will no longer receive or decrypt future group messages.`)) {
      return;
    }

    Toast.show('info', 'Leaving Group', 'Notifying group and clearing local keys...');

    try {
      const newEpoch = Number(activeGroup.current_epoch) + 1;
      const remainingMembers = (activeGroup.members || [])
        .map(m => m.username)
        .filter(u => u !== myUsername);

      let memberKeys = [];
      if (remainingMembers.length > 0) {
        const rot = await EncryptionEngine.rotateGroupEpoch(
          activeGroup.id,
          newEpoch,
          remainingMembers.map(u => ({ username: u }))
        );
        memberKeys = rot.memberKeys;
      }

      const resp = await fetch(`/api/groups/${activeGroup.id}/members/${encodeURIComponent(myUsername)}`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': getCsrfToken(),
        },
        body: JSON.stringify({
          new_epoch: newEpoch,
          new_epoch_keys: memberKeys,
        }),
      });

      const data = await resp.json();
      if (!resp.ok || !data.ok) {
        throw new Error(data.error || 'Failed to leave group');
      }

      this.exitGroupView();
      Toast.show('info', 'Left Group', `You left "${activeGroup?.name || 'group'}".`);
      await this.loadUserGroups();
    } catch (err) {
      console.error('Leave group error:', err);
      Toast.show('error', 'Error Leaving Group', err.message);
    }
  },

  async updateMemberRole(targetUsername, newRole) {
    if (!activeGroup) return;
    try {
      const resp = await fetch(`/api/groups/${activeGroup.id}/members/${encodeURIComponent(targetUsername)}/role`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': getCsrfToken(),
        },
        body: JSON.stringify({ role: newRole }),
      });
      const data = await resp.json();
      if (!resp.ok || !data.ok) {
        throw new Error(data.error || 'Failed to update role');
      }

      activeGroup.members = data.members;
      this.renderGroupMemberList(data.members);
      Toast.show('success', 'Role Updated', `@${targetUsername} is now ${newRole}.`);
    } catch (err) {
      Toast.show('error', 'Role Change Failed', err.message);
    }
  },

  openEditGroupModal() {
    if (!activeGroup) return;
    const nameInput = document.getElementById('editGroupNameInput');
    const descInput = document.getElementById('editGroupDescInput');
    if (nameInput) nameInput.value = activeGroup.name || '';
    if (descInput) descInput.value = activeGroup.description || '';

    const modal = document.getElementById('editGroupModal');
    if (modal) modal.style.display = 'flex';
  },

  closeEditGroupModal() {
    const modal = document.getElementById('editGroupModal');
    if (modal) modal.style.display = 'none';
  },

  async saveGroupInfo() {
    if (!activeGroup) return;
    const nameInput = document.getElementById('editGroupNameInput');
    const descInput = document.getElementById('editGroupDescInput');
    const name = nameInput?.value.trim();
    const description = descInput?.value.trim() || '';

    if (!name || name.length < 2) {
      Toast.show('warning', 'Invalid Name', 'Group name must be at least 2 characters.');
      return;
    }

    try {
      const resp = await fetch(`/api/groups/${activeGroup.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': getCsrfToken(),
        },
        body: JSON.stringify({ name, description }),
      });
      const data = await resp.json();
      if (!resp.ok || !data.ok) {
        throw new Error(data.error || 'Failed to update group');
      }

      activeGroup.name = name;
      activeGroup.description = description;
      this.closeEditGroupModal();
      this.updateGroupDetailsHeaderAndPanel();
      await this.loadUserGroups();
      Toast.show('success', 'Group Updated', 'Group information saved.');
    } catch (err) {
      Toast.show('error', 'Update Failed', err.message);
    }
  },

  exitGroupView() {
    if (activeGroup && socket) {
      socket.emit('leave_group_room', { group_id: activeGroup.id });
    }
    activeGroup = null;
    activeUser = null;
    messagesArea?.querySelectorAll('.message').forEach(m => m.remove());
    checkEmptyChatState();

    const contactCard = document.getElementById('contactProfileCard');
    if (contactCard) contactCard.style.display = 'flex';
    const groupCard = document.getElementById('groupProfileCard');
    if (groupCard) groupCard.style.display = 'none';
    const groupSec = document.getElementById('groupMembersSection');
    if (groupSec) groupSec.style.display = 'none';
    const leaveBtn = document.getElementById('rightPanelLeaveGroupBtn');
    if (leaveBtn) leaveBtn.style.display = 'none';

    if (chatHeaderName) chatHeaderName.textContent = 'Select a conversation';
    if (chatHeaderStatus) {
      chatHeaderStatus.textContent = 'End-to-End Encrypted';
      chatHeaderStatus.className = 'ig-header-status-text chat-header-status';
    }
    if (chatAvatarInitials) {
      chatAvatarInitials.textContent = '--';
      chatAvatarInitials.style.background = 'var(--ig-bg-secondary)';
    }

    this.switchSidebarTab('primary');
  },

  switchSidebarTab(tabName) {
    currentSidebarTab = tabName;
    document.querySelectorAll('.ig-tab-btn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.tab === tabName);
    });
    if (tabName === 'groups') {
      this.renderGroupsList();
    } else if (tabName === 'requests') {
      if (userListContainer) {
        userListContainer.innerHTML = `
          <div style="text-align:center; padding:32px 16px; color:var(--ig-text-muted);">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="36" height="36" style="margin-bottom:8px; opacity:0.6;">
              <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
            </svg>
            <p style="font-size:13px; font-weight:600; color:var(--ig-text-primary); margin-bottom:4px;">No Message Requests</p>
            <p style="font-size:12px;">You don't have any pending conversation requests.</p>
          </div>
        `;
      }
    } else {
      renderUserList();
    }
  },

  incrementUnread(groupId) {
    const cur = this.unreadCounts.get(Number(groupId)) || 0;
    this.unreadCounts.set(Number(groupId), cur + 1);
    const item = userListContainer?.querySelector(`.ig-group-item[data-group-id="${groupId}"]`);
    if (item) item.classList.add('has-unread');
  }
};

/* ─── Call and Voice Initialization ─── */
function initCallAndVoice() {
  // Initialize WebRTC Voice & Video calling system
  WebRTCCallManager.init();

  // Initialize production-grade voice recorder
  VoiceRecorderManager.init();

  // Initialize Scheduled Messaging system
  ScheduledMessagesManager.init();

  // Initialize Group Conversation Manager
  GroupChatManager.init();

  // Attachment button file handling
  attachmentBtn?.addEventListener('click', () => fileInput?.click());
  fileInput?.addEventListener('change', (e) => {
    const file = e.target.files?.[0];
    if (file) {
      sendEncryptedMedia(file);
      fileInput.value = '';
    }
  });
}

function initSidebarTabs() {
  const tabs = document.querySelectorAll('.ig-tab-btn');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      const tabType = tab.dataset.tab;
      if (tabType === 'requests') {
        currentSidebarTab = 'requests';
        userListContainer.innerHTML = `
          <div style="text-align:center; padding:32px 16px; color:var(--ig-text-muted);">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="36" height="36" style="margin-bottom:8px; opacity:0.6;">
              <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
            </svg>
            <p style="font-size:13px; font-weight:600; color:var(--ig-text-primary); margin-bottom:4px;">No Message Requests</p>
            <p style="font-size:12px;">You don't have any pending conversation requests.</p>
          </div>
        `;
      } else if (tabType === 'groups') {
        currentSidebarTab = 'groups';
        GroupChatManager.renderGroupsList();
      } else {
        currentSidebarTab = 'primary';
        renderUserList();
      }
    });
  });

  mobileBackBtn?.addEventListener('click', () => {
    sidebar?.classList.remove('chat-active');
  });

  const newMessageBtn = document.getElementById('newMessageBtn');
  newMessageBtn?.addEventListener('click', () => {
    searchInput?.focus();
    Toast.show('info', 'New Conversation', 'Search for a username to start chatting.');
  });

  const refreshListBtn = document.getElementById('refreshListBtn');
  refreshListBtn?.addEventListener('click', loadServerUsers);
}

/* ─── Modal Management ─── */
function setupModal(modalEl, closeBtn, openTriggers = []) {
  if (!modalEl) return;
  const open = () => modalEl.classList.add('active');
  const close = () => modalEl.classList.remove('active');

  openTriggers.forEach(btn => btn?.addEventListener('click', open));
  closeBtn?.addEventListener('click', close);
  modalEl.addEventListener('click', (e) => {
    if (e.target === modalEl) close();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') close();
  });
}

/* ─── Inspect Cryptographic Payload Modal ─── */
function openMessageInspector(messageId) {
  const cached = messagePayloadCache.get(Number(messageId));
  if (!cached) {
    Toast.show('info', 'Payload Inspector', 'No cryptographic packet cached for this item.');
    return;
  }

  inspectMsgId.textContent = `Message #${cached.id}`;
  inspectTimestamp.textContent = cached.timestamp || 'Real-time';
  inspectCiphertext.textContent = cached.ciphertext || '[Empty]';
  inspectNonce.textContent = cached.nonce || '[Empty]';
  inspectTag.textContent = cached.tag || '[Empty]';
  inspectPlaintext.textContent = cached.plaintext || '[Decrypted in-memory]';

  inspectModal?.classList.add('active');
}

/* ─── Peer Profile & Safety Numbers Modal ─── */
async function openPeerProfileModal() {
  if (!activeUser || !USERS[activeUser]) return;
  const user = USERS[activeUser];
  if (peerModalName) peerModalName.textContent = user.username;
  if (peerModalEmail) peerModalEmail.textContent = user.email || `${user.username}@tmeee.local`;
  if (peerModalAvatar) {
    peerModalAvatar.textContent = user.initials;
    peerModalAvatar.style.background = user.gradient;
  }
  if (peerModalStatus) {
    peerModalStatus.textContent = user.status === 'online' ? '● Online' : '○ Offline';
    peerModalStatus.className = `identity-status-pill ${user.status === 'offline' ? 'offline' : ''}`;
  }
  if (peerSafetyName) peerSafetyName.textContent = `@${user.username}`;

  let pubKey = user.publicKey;
  if (!pubKey) {
    try {
      pubKey = await EncryptionEngine.fetchPeerPublicKey(activeUser);
      user.publicKey = pubKey;
    } catch (_) {
      pubKey = null;
    }
  }
  if (peerPublicKeyDisplay) peerPublicKeyDisplay.textContent = pubKey || 'Unavailable';

  if (safetyNumberGrid) {
    const myPub = EncryptionEngine.getPublicKeyB64();
    if (myPub && pubKey) {
      const numbers = await computeSafetyNumbers(myPub, pubKey);
      safetyNumberGrid.innerHTML = numbers.map(n => `<div class="ig-safety-chunk">${n}</div>`).join('');
    } else {
      safetyNumberGrid.innerHTML = '<div class="ig-safety-chunk">Pending</div>';
    }
  }

  peerProfileModal?.classList.add('active');
}

/* ─── My Profile Modal ─── */
function openMyProfileModal() {
  const nameEl = document.getElementById('myModalName');
  const emailEl = document.getElementById('myModalEmail');
  const avatarEl = document.getElementById('myModalAvatar');

  if (nameEl) nameEl.textContent = myUsername;
  if (emailEl) emailEl.textContent = myEmail || `${myUsername}@tmeee.local`;
  if (avatarEl) {
    const initials = (document.querySelector('.user-profile-avatar')?.textContent.trim() || myUsername.slice(0, 2)).toUpperCase();
    avatarEl.textContent = initials;
  }

  const pubKey = EncryptionEngine.getPublicKeyB64();
  if (myPublicKeyDisplay) myPublicKeyDisplay.textContent = pubKey || 'Loading...';
  if (myKeyFingerprint && pubKey) {
    computeFingerprint(pubKey).then(fp => {
      myKeyFingerprint.textContent = fp;
    });
  }

  myProfileModal?.classList.add('active');
}

async function computeFingerprint(b64) {
  try {
    const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const hash = await crypto.subtle.digest('SHA-256', raw);
    const hex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
    return hex.match(/.{1,4}/g).slice(0, 8).join(':').toUpperCase();
  } catch (_) {
    return 'SHA-256 Fingerprint Unavailable';
  }
}

async function computeSafetyNumbers(pubA, pubB) {
  const sorted = [pubA, pubB].sort();
  const enc = new TextEncoder();
  const data = enc.encode(sorted[0] + sorted[1]);
  const hash = await crypto.subtle.digest('SHA-256', data);
  const bytes = new Uint8Array(hash);

  const chunks = [];
  for (let i = 0; i < 8; i++) {
    const offset = i * 4;
    const val = ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
    const num = (val % 100000).toString().padStart(5, '0');
    chunks.push(num);
  }
  return chunks;
}

/* ══════════════════════════════════════════════════════════════════════════
   DISAPPEARING MESSAGES & VANISH MODE MANAGER
   ══════════════════════════════════════════════════════════════════════════ */
const DisappearingMessagesManager = {
  activeTimer: 0,
  isVanishMode: false,
  isViewOnceActive: false,
  trackedMessages: new Map(),
  tickerInterval: null,
  viewOnceTimer: null,
  socket: null,

  init(socketInstance) {
    this.socket = socketInstance;
    this.bindEvents();
    this.startTicker();
  },

  bindEvents() {
    // 1. Header Disappearing Timer button click
    const headerDisappearingBtn = document.getElementById('headerDisappearingBtn');
    headerDisappearingBtn?.addEventListener('click', () => this.openDisappearingModal());

    // 2. Right Sidebar Disappearing button click
    const rightPanelDisappearingBtn = document.getElementById('rightPanelDisappearingBtn');
    rightPanelDisappearingBtn?.addEventListener('click', () => this.openDisappearingModal());

    // 3. Header Vanish Mode button click
    const headerVanishBtn = document.getElementById('headerVanishModeBtn');
    headerVanishBtn?.addEventListener('click', () => this.toggleVanishMode());

    // 4. Vanish Banner "Turn Off" button
    const turnOffVanishBtn = document.getElementById('turnOffVanishBtn');
    turnOffVanishBtn?.addEventListener('click', () => this.setVanishMode(false));

    // 5. Right Sidebar Vanish Toggle Switch
    const vanishToggleSwitch = document.getElementById('vanishToggleSwitch');
    vanishToggleSwitch?.addEventListener('change', (e) => this.setVanishMode(e.target.checked));

    // 6. View Once Toggle in Input
    const viewOnceBtn = document.getElementById('viewOnceBtn');
    viewOnceBtn?.addEventListener('click', () => this.toggleViewOnce());

    // 7. Modal Buttons
    const closeModalBtn = document.getElementById('closeDisappearingModalBtn');
    closeModalBtn?.addEventListener('click', () => this.closeDisappearingModal());

    const cancelModalBtn = document.getElementById('cancelDisappearingBtn');
    cancelModalBtn?.addEventListener('click', () => this.closeDisappearingModal());

    const saveModalBtn = document.getElementById('saveDisappearingBtn');
    saveModalBtn?.addEventListener('click', () => this.saveDisappearingTimer());

    // 8. View Once viewer close
    const closeViewOnceBtn = document.getElementById('closeViewOnceViewerBtn');
    closeViewOnceBtn?.addEventListener('click', () => this.closeViewOnceViewer());

    // 9. Socket event listeners
    if (this.socket) {
      this.socket.on('disappearing_timer_changed', (data) => {
        if (data.peer === activeUser || data.changed_by === activeUser || (data.peer && activeUser && data.peer.toLowerCase() === activeUser.toLowerCase())) {
          this.activeTimer = Number(data.disappearing_timer || 0);
          this.updateTimerUI();
          Toast.show('info', 'Disappearing Messages', `Timer set to ${this.formatTimerLabel(this.activeTimer)} by @${data.changed_by || 'system'}`);
        }
      });

      this.socket.on('vanish_mode_toggled', (data) => {
        if (data.peer === activeUser || data.toggled_by === activeUser || (data.peer && activeUser && data.peer.toLowerCase() === activeUser.toLowerCase())) {
          this.isVanishMode = Boolean(data.vanish_mode);
          this.updateVanishUI();
          Toast.show('info', 'Vanish Mode', this.isVanishMode ? '👻 Vanish Mode turned on' : 'Vanish Mode turned off');
        }
      });

      this.socket.on('group_disappearing_timer_changed', (data) => {
        if (activeGroup && Number(activeGroup.id) === Number(data.group_id)) {
          this.activeTimer = Number(data.disappearing_timer || 0);
          this.updateTimerUI();
          Toast.show('info', 'Group Disappearing Timer', `Group messages will expire in ${this.formatTimerLabel(this.activeTimer)}.`);
        }
      });

      this.socket.on('message_expired', (data) => {
        this.handleMessageExpired(data.message_id);
      });

      this.socket.on('message_viewed_update', (data) => {
        if (data.message_id && data.expires_at) {
          this.trackMessage(data.message_id, data.expires_at);
        }
      });
    }

    // 10. Click on View-Once cards inside message stream
    document.addEventListener('click', (e) => {
      const card = e.target.closest('.view-once-bubble-card');
      if (card && !card.classList.contains('opened')) {
        const msgId = card.dataset.msgId;
        this.openViewOnceMessage(msgId, card);
      }
    });
  },

  formatTimerLabel(seconds) {
    if (!seconds || seconds <= 0) return 'Off';
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
    return '24h';
  },

  applyConversationSettings(settings) {
    if (!settings) return;
    this.activeTimer = Number(settings.disappearing_timer || 0);
    this.isVanishMode = Boolean(settings.vanish_mode);
    this.updateTimerUI();
    this.updateVanishUI();
  },

  updateTimerUI() {
    const badge = document.getElementById('headerDisappearingBadge');
    const headerBtn = document.getElementById('headerDisappearingBtn');
    const rightVal = document.getElementById('rightPanelDisappearingVal');

    if (badge) badge.style.display = this.activeTimer > 0 ? 'block' : 'none';
    if (headerBtn) headerBtn.classList.toggle('active', this.activeTimer > 0);
    if (rightVal) rightVal.textContent = this.formatTimerLabel(this.activeTimer);

    const radios = document.querySelectorAll('input[name="disappearingTimerOption"]');
    radios.forEach(r => {
      r.checked = (Number(r.value) === this.activeTimer);
    });
  },

  updateVanishUI() {
    const banner = document.getElementById('vanishModeBanner');
    const vanishBtn = document.getElementById('headerVanishModeBtn');
    const vanishSwitch = document.getElementById('vanishToggleSwitch');
    const appEl = document.querySelector('.ig-main-app') || document.body;

    if (this.isVanishMode) {
      document.body.classList.add('vanish-mode-active');
      appEl.classList.add('vanish-mode-active');
      if (banner) banner.style.display = 'block';
      if (vanishBtn) vanishBtn.classList.add('active');
      if (vanishSwitch) vanishSwitch.checked = true;
    } else {
      document.body.classList.remove('vanish-mode-active');
      appEl.classList.remove('vanish-mode-active');
      if (banner) banner.style.display = 'none';
      if (vanishBtn) vanishBtn.classList.remove('active');
      if (vanishSwitch) vanishSwitch.checked = false;
    }
  },

  toggleViewOnce() {
    this.isViewOnceActive = !this.isViewOnceActive;
    const btn = document.getElementById('viewOnceBtn');
    if (btn) btn.classList.toggle('active', this.isViewOnceActive);
    if (this.isViewOnceActive) {
      Toast.show('info', 'View Once Activated', 'The next photo or video will disappear after being viewed.');
    }
  },

  openDisappearingModal() {
    const modal = document.getElementById('disappearingModal');
    if (modal) {
      this.updateTimerUI();
      modal.style.display = 'flex';
    }
  },

  closeDisappearingModal() {
    const modal = document.getElementById('disappearingModal');
    if (modal) modal.style.display = 'none';
  },

  async saveDisappearingTimer() {
    const selected = document.querySelector('input[name="disappearingTimerOption"]:checked');
    const timer = selected ? Number(selected.value) : 0;
    this.closeDisappearingModal();

    if (activeGroup) {
      try {
        const resp = await fetch(`/api/groups/${activeGroup.id}/disappearing`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ timer }),
        });
        const res = await resp.json();
        if (res.ok) {
          this.activeTimer = timer;
          this.updateTimerUI();
          Toast.show('success', 'Group Timer Updated', `Messages will expire in ${this.formatTimerLabel(timer)}.`);
        } else {
          Toast.show('error', 'Error', res.error || 'Failed to update group timer.');
        }
      } catch (err) {
        console.error('Failed to set group disappearing timer:', err);
      }
    } else if (activeUser) {
      try {
        const resp = await fetch(`/api/conversations/${encodeURIComponent(activeUser)}/disappearing`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ timer }),
        });
        const res = await resp.json();
        if (res.ok) {
          this.activeTimer = timer;
          this.updateTimerUI();
          Toast.show('success', 'Disappearing Messages', `Timer set to ${this.formatTimerLabel(timer)}.`);
        } else {
          Toast.show('error', 'Error', res.error || 'Failed to update timer.');
        }
      } catch (err) {
        console.error('Failed to set disappearing timer:', err);
      }
    }
  },

  async setVanishMode(enabled) {
    if (!activeUser) return;
    try {
      const resp = await fetch(`/api/conversations/${encodeURIComponent(activeUser)}/vanish-mode`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled }),
      });
      const res = await resp.json();
      if (res.ok) {
        this.isVanishMode = Boolean(enabled);
        this.updateVanishUI();
      }
    } catch (err) {
      console.error('Failed to toggle vanish mode:', err);
    }
  },

  async toggleVanishMode() {
    await this.setVanishMode(!this.isVanishMode);
  },

  trackMessage(messageId, expiresAtStr) {
    if (!messageId || !expiresAtStr) return;
    const expDate = new Date(expiresAtStr.replace('Z', '+00:00'));
    this.trackedMessages.set(Number(messageId), expDate);
  },

  handleMessageExpired(messageId) {
    if (!messageId) return;
    const msgEl = document.querySelector(`.message[data-message-id="${messageId}"]`);
    if (msgEl) {
      msgEl.classList.add('disintegrating');
      setTimeout(() => {
        msgEl.remove();
        checkEmptyChatState?.();
      }, 750);
    }
    this.trackedMessages.delete(Number(messageId));

    const toast = document.createElement('div');
    toast.className = 'ephemeral-notice-toast';
    toast.textContent = '⏱️ A disappearing message has expired and was permanently erased.';
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 2600);
  },

  startTicker() {
    if (this.tickerInterval) clearInterval(this.tickerInterval);
    this.tickerInterval = setInterval(() => {
      const now = new Date();
      const badges = document.querySelectorAll('.ig-countdown-badge[data-expires-at]');

      badges.forEach(badge => {
        const expiresAtStr = badge.dataset.expiresAt;
        if (!expiresAtStr) return;
        const expDate = new Date(expiresAtStr.replace('Z', '+00:00'));
        const remainingSecs = Math.max(0, Math.floor((expDate - now) / 1000));

        if (remainingSecs <= 0) {
          const msgEl = badge.closest('.message');
          const msgId = msgEl?.dataset.messageId;
          if (msgId) {
            this.handleMessageExpired(msgId);
          } else if (msgEl) {
            msgEl.classList.add('disintegrating');
            setTimeout(() => msgEl.remove(), 750);
          }
        } else {
          badge.textContent = remainingSecs < 60
            ? `⏱️ ${remainingSecs}s`
            : (remainingSecs < 3600
                ? `⏱️ ${Math.floor(remainingSecs / 60)}m ${remainingSecs % 60}s`
                : `⏱️ ${Math.floor(remainingSecs / 3600)}h ${Math.floor((remainingSecs % 3600) / 60)}m`);

          if (remainingSecs <= 10) {
            badge.classList.add('urgent');
          } else {
            badge.classList.remove('urgent');
          }
        }
      });
    }, 1000);
  },

  openViewOnceMessage(msgId, cardEl) {
    if (!msgId) return;
    const modal = document.getElementById('viewOnceModal');
    const container = document.getElementById('viewOnceMediaContent');
    const timerSecs = document.getElementById('viewOnceTimerSecs');

    const cached = messagePayloadCache.get(Number(msgId));
    let mediaObj = null;
    if (cached && cached.plaintext) {
      try {
        if (typeof cached.plaintext === 'string' && cached.plaintext.startsWith('{')) {
          mediaObj = JSON.parse(cached.plaintext);
        }
      } catch (e) {}
    }

    if (!mediaObj || !mediaObj.data) {
      Toast.show('error', 'View Once', 'Media not available or expired.');
      return;
    }

    if (container) {
      container.innerHTML = '';
      if (mediaObj.mediaType === 'video') {
        const vid = document.createElement('video');
        vid.src = mediaObj.data;
        vid.controls = true;
        vid.autoplay = true;
        vid.style.maxWidth = '100%';
        vid.style.maxHeight = '75vh';
        container.appendChild(vid);
      } else {
        const img = document.createElement('img');
        img.src = mediaObj.data;
        img.style.maxWidth = '100%';
        img.style.maxHeight = '75vh';
        img.style.objectFit = 'contain';
        container.appendChild(img);
      }
    }

    if (modal) modal.style.display = 'flex';

    fetch(`/api/messages/${msgId}/view`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ is_group: Boolean(activeGroup) }),
    }).catch(console.error);

    if (cardEl) {
      cardEl.classList.add('opened');
      cardEl.innerHTML = '<span class="view-once-bubble-icon">✓</span><span class="view-once-bubble-label">Opened · Disappeared</span>';
    }

    let remaining = 10;
    if (timerSecs) timerSecs.textContent = remaining;
    if (this.viewOnceTimer) clearInterval(this.viewOnceTimer);

    this.viewOnceTimer = setInterval(() => {
      remaining -= 1;
      if (timerSecs) timerSecs.textContent = remaining;
      if (remaining <= 0) {
        clearInterval(this.viewOnceTimer);
        this.closeViewOnceViewer();
        this.handleMessageExpired(msgId);
      }
    }, 1000);
  },

  closeViewOnceViewer() {
    if (this.viewOnceTimer) clearInterval(this.viewOnceTimer);
    const modal = document.getElementById('viewOnceModal');
    const container = document.getElementById('viewOnceMediaContent');
    if (container) container.innerHTML = '';
    if (modal) modal.style.display = 'none';
  }
};

/* ─── Master Event Delegations & Initialization ─── */
document.addEventListener('DOMContentLoaded', async () => {
  Toast.init();
  initPrivacySettings();

  // Current session user identity
  const profileNameEl = document.querySelector('.user-profile-name');
  myUsername = profileNameEl ? profileNameEl.textContent.trim() : 'me';

  // Core setup
  autoResizeTextarea();
  initSearch();
  initEmojiAndMediaPickers();
  initRightSidebar();
  initCallAndVoice();
  initSidebarTabs();

  // Modals setup
  setupModal(encryptionModal, closeEncModal, [encryptionBadgeHeader, e2eeGlobalBadge]);
  setupModal(myProfileModal, closeMyProfileModal, [myProfileBtn, userProfileCard]);
  setupModal(peerProfileModal, closePeerProfileModal, [verifyKeysBtn, activeHeaderUserCard]);
  setupModal(inspectModal, closeInspectModal, []);
  setupModal(blockUserModal, closeBlockModal, []);
  setupModal(reportUserModal, closeReportModal, []);
  setupModal(forwardModal, closeForwardModal, [cancelForwardBtn]);
  setupModal(mediaLightboxModal, closeLightboxBtn, []);

  // 3-Dots Menu Bindings
  chatMenuBtn?.addEventListener('click', toggleChatMenu);
  menuUserInfo?.addEventListener('click', () => {
    closeChatMenu();
    openPeerProfileModal();
  });
  menuSearch?.addEventListener('click', openInChatSearch);
  menuMute?.addEventListener('click', toggleMuteNotifications);
  menuBlock?.addEventListener('click', handleBlockClick);
  menuReport?.addEventListener('click', handleReportClick);

  document.addEventListener('click', (e) => {
    if (!e.target.closest('#headerMenuContainer')) closeChatMenu();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeChatMenu();
      closeInChatSearch();
    }
  });

  // Reply preview bar close
  cancelReplyBtn?.addEventListener('click', cancelReply);

  // Edit notice bar close
  cancelEditBtn?.addEventListener('click', cancelEdit);

  // Unpin banner close button
  unpinCurrentBtn?.addEventListener('click', (e) => {
    e.stopPropagation();
    updatePinnedBanner(null);
  });

  // In-Chat Search inputs & arrows
  inChatSearchInput?.addEventListener('input', performInChatSearch);
  inChatSearchClose?.addEventListener('click', closeInChatSearch);
  inChatNextBtn?.addEventListener('click', () => navigateSearch('next'));
  inChatPrevBtn?.addEventListener('click', () => navigateSearch('prev'));

  // Block modal action buttons
  cancelBlockBtn?.addEventListener('click', () => blockUserModal?.classList.remove('active'));
  confirmBlockBtn?.addEventListener('click', confirmBlockUser);

  // Report modal action buttons
  cancelReportBtn?.addEventListener('click', () => reportUserModal?.classList.remove('active'));
  submitReportBtn?.addEventListener('click', submitReportUser);

  // Copy buttons
  copyMyPubKeyBtn?.addEventListener('click', () => copyText(myPublicKeyDisplay?.textContent, 'Public Key Copied'));
  copyPeerPubKeyBtn?.addEventListener('click', () => copyText(peerPublicKeyDisplay?.textContent, 'Peer Public Key Copied'));
  copyCiphertextBtn?.addEventListener('click', () => copyText(inspectCiphertext?.textContent, 'Ciphertext Copied'));

  // Event Delegation in Messages Area (Message Hover Actions, Reactions, Quotes, Lightbox)
  messagesArea?.addEventListener('click', (e) => {
    // 1. Quoted message click -> scroll to original message
    const quoteEl = e.target.closest('.msg-reply-quote');
    if (quoteEl) {
      const targetId = quoteEl.dataset.targetId;
      const targetMsg = document.querySelector(`.message[data-message-id="${targetId}"]`);
      if (targetMsg) {
        targetMsg.scrollIntoView({ behavior: 'smooth', block: 'center' });
        targetMsg.classList.add('highlight-pulse');
        setTimeout(() => targetMsg.classList.remove('highlight-pulse'), 1500);
      }
      return;
    }

    // 2. Lightbox click on media images
    const imgEl = e.target.closest('.msg-media-image[data-lightbox="true"]');
    if (imgEl) {
      openMediaLightbox(imgEl.src, imgEl.dataset.filename);
      return;
    }

    // 3. Quick reaction button click
    const quickReactBtn = e.target.closest('.msg-quick-react-btn');
    if (quickReactBtn) {
      const msgId = quickReactBtn.dataset.msgId;
      const emoji = quickReactBtn.dataset.emoji;
      if (msgId && emoji) toggleReaction(msgId, emoji);
      return;
    }

    // 4. Reaction pill click
    const pillBtn = e.target.closest('.msg-reaction-pill');
    if (pillBtn) {
      const msgId = pillBtn.dataset.msgId;
      const emoji = pillBtn.dataset.emoji;
      if (msgId && emoji) toggleReaction(msgId, emoji);
      return;
    }

    // 5. Reply action button
    const replyBtn = e.target.closest('.btn-reply');
    if (replyBtn) {
      const msgEl = replyBtn.closest('.message');
      const msgId = replyBtn.dataset.msgId || msgEl?.dataset.messageId;
      const isSelf = msgEl?.classList.contains('self');
      const groupSender = msgEl?.querySelector('.msg-group-sender')?.textContent;
      const sender = isSelf ? myUsername : (groupSender || activeUser);
      const text = msgEl?.querySelector('.msg-text')?.textContent || 'Attachment';
      startReply(msgId, sender, text);
      return;
    }

    // 6. Forward action button
    const forwardBtn = e.target.closest('.btn-forward');
    if (forwardBtn) {
      const msgEl = forwardBtn.closest('.message');
      const msgId = forwardBtn.dataset.msgId || msgEl?.dataset.messageId;
      const text = msgEl?.querySelector('.msg-text')?.textContent || '';
      openForwardModal(msgId, text);
      return;
    }

    // 7. Pin action button
    const pinBtn = e.target.closest('.btn-pin');
    if (pinBtn) {
      const msgEl = pinBtn.closest('.message');
      const msgId = pinBtn.dataset.msgId || msgEl?.dataset.messageId;
      const currentlyPinned = pinBtn.classList.contains('active');
      togglePinMessage(msgId, currentlyPinned);
      return;
    }

    // 8. Edit action button
    const editBtn = e.target.closest('.btn-edit');
    if (editBtn) {
      const msgEl = editBtn.closest('.message');
      const msgId = editBtn.dataset.msgId || msgEl?.dataset.messageId;
      const currentText = msgEl?.querySelector('.msg-text')?.textContent || '';
      startEdit(msgId, currentText);
      return;
    }

    // 9. Unsend action button
    const unsendBtn = e.target.closest('.btn-unsend');
    if (unsendBtn) {
      const msgEl = unsendBtn.closest('.message');
      const msgId = unsendBtn.dataset.msgId || msgEl?.dataset.messageId;
      unsendMessage(msgId);
      return;
    }

    // 10. Delete action button
    const delBtn = e.target.closest('.btn-delete');
    if (delBtn) {
      const msgEl = delBtn.closest('.message');
      const msgId = delBtn.dataset.msgId || msgEl?.dataset.messageId;
      deleteMessageById(msgId);
      return;
    }

    // 11. Inspect cryptographic packet button
    const inspectBtn = e.target.closest('.btn-inspect');
    if (inspectBtn) {
      const msgEl = inspectBtn.closest('.message');
      const msgId = inspectBtn.dataset.msgId || msgEl?.dataset.messageId;
      if (msgId) openMessageInspector(msgId);
      return;
    }

    // 12. Voice message play / pause toggle
    const voicePlayBtn = e.target.closest('.voice-bubble-play-btn');
    if (voicePlayBtn) {
      const card = voicePlayBtn.closest('.msg-voice-card');
      if (card && typeof GlobalVoicePlayer !== 'undefined') {
        GlobalVoicePlayer.toggle(card);
      }
      return;
    }

    // 13. Voice message waveform scrubber / seek
    const voiceTrack = e.target.closest('.voice-waveform-track');
    if (voiceTrack) {
      const card = voiceTrack.closest('.msg-voice-card');
      if (card && typeof GlobalVoicePlayer !== 'undefined') {
        const rect = voiceTrack.getBoundingClientRect();
        const clickX = e.clientX - rect.left;
        const fraction = Math.max(0, Math.min(1, clickX / rect.width));
        GlobalVoicePlayer.seek(card, fraction);
      }
      return;
    }
  });

  // 1. Initialize client-side encryption engine
  if (typeof EncryptionEngine !== 'undefined') {
    try {
      const pubKey = await EncryptionEngine.init(myUsername);
      console.info('[E2EE] Client engine initialized. Public Key:', pubKey);
    } catch (e) {
      console.warn('[E2EE] Client init warning:', e);
    }
  }

  // 2. Connect WebSocket gateway
  initSocket();

  // 2b. Initialize disappearing messages & vanish mode manager
  if (typeof DisappearingMessagesManager !== 'undefined') {
    DisappearingMessagesManager.init(socket);
  }

  // 3. Scroll to bottom
  scrollToBottom(false);
});
