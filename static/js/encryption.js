// encryption.js - Complete End-to-End Encryption Library
// Place this file in: static/js/encryption.js

/**
 * E2EEManager - Handles all encryption/decryption operations
 * Uses Web Crypto API for browser-native cryptography
 */
class E2EEManager {
    constructor() {
        this.keyPair = null;           // User's RSA keypair
        this.roomKeys = new Map();     // Map of roomId -> AES key
        this.isInitialized = false;
        this.initPromise = null;       // Prevent multiple initializations
    }

    /**
     * Initialize user's keypair
     * Called automatically when needed
     */
    async initialize() {
        // Prevent multiple initializations
        if (this.initPromise) {
            return this.initPromise;
        }

        this.initPromise = (async () => {
            try {
                console.log('🔐 Initializing E2EE...');
                
                // Check if user has existing keys in localStorage
                const storedKeys = localStorage.getItem('userKeyPair');
                
                if (storedKeys) {
                    // Import existing keys
                    console.log('📥 Loading existing keys...');
                    const keys = JSON.parse(storedKeys);
                    
                    this.keyPair = {
                        publicKey: await crypto.subtle.importKey(
                            'jwk',
                            keys.publicKey,
                            {
                                name: 'RSA-OAEP',
                                hash: 'SHA-256',
                            },
                            true,
                            ['encrypt']
                        ),
                        privateKey: await crypto.subtle.importKey(
                            'jwk',
                            keys.privateKey,
                            {
                                name: 'RSA-OAEP',
                                hash: 'SHA-256',
                            },
                            true,
                            ['decrypt']
                        )
                    };
                    
                    console.log('✅ Keys loaded from storage');
                } else {
                    // Generate new keypair
                    console.log('🔑 Generating new keypair...');
                    
                    this.keyPair = await crypto.subtle.generateKey(
                        {
                            name: 'RSA-OAEP',
                            modulusLength: 2048,
                            publicExponent: new Uint8Array([1, 0, 1]),
                            hash: 'SHA-256',
                        },
                        true,
                        ['encrypt', 'decrypt']
                    );

                    // Export and store keys
                    const publicKeyJwk = await crypto.subtle.exportKey('jwk', this.keyPair.publicKey);
                    const privateKeyJwk = await crypto.subtle.exportKey('jwk', this.keyPair.privateKey);
                    
                    localStorage.setItem('userKeyPair', JSON.stringify({
                        publicKey: publicKeyJwk,
                        privateKey: privateKeyJwk,
                        createdAt: new Date().toISOString()
                    }));

                    // Send public key to server
                    await this.sendPublicKeyToServer(publicKeyJwk);
                    
                    console.log('✅ New keypair generated and stored');
                }

                this.isInitialized = true;
                console.log('✅ E2EE initialized successfully');
                
            } catch (error) {
                console.error('❌ E2EE initialization failed:', error);
                this.isInitialized = false;
                throw error;
            }
        })();

        return this.initPromise;
    }

    /**
     * Send public key to server
     */
    async sendPublicKeyToServer(publicKeyJwk) {
        try {
            const csrftoken = this.getCookie('csrftoken');
            
            const response = await fetch('/api/upload-public-key/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrftoken
                },
                credentials: 'same-origin',
                body: JSON.stringify({
                    public_key: JSON.stringify(publicKeyJwk)
                })
            });

            const data = await response.json();
            
            if (!data.success) {
                console.warn('⚠️ Failed to upload public key:', data.error);
            } else {
                console.log('✅ Public key uploaded to server');
            }
        } catch (error) {
            console.error('❌ Error uploading public key:', error);
        }
    }

    /**
     * Generate a new room key (AES-GCM 256-bit)
     */
    async generateRoomKey() {
        return await crypto.subtle.generateKey(
            {
                name: 'AES-GCM',
                length: 256
            },
            true,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Get or create room key
     */
    async getRoomKey(roomId) {
        // Check cache first
        if (this.roomKeys.has(roomId)) {
            return this.roomKeys.get(roomId);
        }

        console.log(`🔑 Getting room key for: ${roomId}`);

        // Try to fetch from server
        const key = await this.fetchRoomKey(roomId);
        if (key) {
            this.roomKeys.set(roomId, key);
            console.log(`✅ Room key fetched for: ${roomId}`);
            return key;
        }

        // Create new room key
        console.log(`🔨 Creating new room key for: ${roomId}`);
        const newKey = await this.generateRoomKey();
        await this.uploadRoomKey(roomId, newKey);
        this.roomKeys.set(roomId, newKey);
        console.log(`✅ New room key created for: ${roomId}`);
        
        return newKey;
    }

    /**
     * Fetch room key from server
     */
    async fetchRoomKey(roomId) {
        try {
            const csrftoken = this.getCookie('csrftoken');
            
            const response = await fetch(`/api/get-room-key/${roomId}/`, {
                method: 'GET',
                headers: {
                    'X-CSRFToken': csrftoken
                },
                credentials: 'same-origin'
            });

            const data = await response.json();
            
            if (data.success && data.encrypted_key) {
                console.log(`📥 Encrypted room key received for: ${roomId}`);
                
                // Decrypt the room key with user's private key
                const encryptedKeyBuffer = this.base64ToArrayBuffer(data.encrypted_key);
                
                const decryptedKeyBuffer = await crypto.subtle.decrypt(
                    {
                        name: 'RSA-OAEP'
                    },
                    this.keyPair.privateKey,
                    encryptedKeyBuffer
                );

                // Import as AES-GCM key
                const keyData = JSON.parse(new TextDecoder().decode(decryptedKeyBuffer));
                
                const roomKey = await crypto.subtle.importKey(
                    'jwk',
                    keyData,
                    { name: 'AES-GCM' },
                    true,
                    ['encrypt', 'decrypt']
                );
                
                console.log(`🔓 Room key decrypted for: ${roomId}`);
                return roomKey;
            }
            
            console.log(`⚠️ No room key found for: ${roomId}`);
            return null;
            
        } catch (error) {
            console.error(`❌ Error fetching room key for ${roomId}:`, error);
            return null;
        }
    }

    /**
     * Upload room key to server (encrypted for current user)
     */
    async uploadRoomKey(roomId, roomKey) {
        try {
            console.log(`📤 Uploading room key for: ${roomId}`);
            
            // Export room key to JWK format
            const keyData = await crypto.subtle.exportKey('jwk', roomKey);
            const keyString = JSON.stringify(keyData);

            // Encrypt with user's public key
            const encryptedKey = await crypto.subtle.encrypt(
                {
                    name: 'RSA-OAEP'
                },
                this.keyPair.publicKey,
                new TextEncoder().encode(keyString)
            );

            const csrftoken = this.getCookie('csrftoken');
            
            const response = await fetch(`/api/upload-room-key/${roomId}/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrftoken
                },
                credentials: 'same-origin',
                body: JSON.stringify({
                    encrypted_key: this.arrayBufferToBase64(encryptedKey)
                })
            });

            const data = await response.json();
            
            if (data.success) {
                console.log(`✅ Room key uploaded for: ${roomId}`);
            } else {
                console.warn(`⚠️ Failed to upload room key for ${roomId}:`, data.error);
            }
            
        } catch (error) {
            console.error(`❌ Error uploading room key for ${roomId}:`, error);
        }
    }

    /**
     * Encrypt a message for a room
     * @param {string} roomId - The room ID
     * @param {string} message - The plaintext message
     * @returns {string} Base64 encoded encrypted message
     */
    async encryptMessage(roomId, message) {
        if (!this.isInitialized) {
            await this.initialize();
        }

        try {
            // Get room key
            const roomKey = await this.getRoomKey(roomId);
            
            // Generate random IV (12 bytes for GCM)
            const iv = crypto.getRandomValues(new Uint8Array(12));
            
            // Encrypt message
            const encodedMessage = new TextEncoder().encode(message);
            const encryptedContent = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                roomKey,
                encodedMessage
            );

            // Combine IV and encrypted content
            const result = new Uint8Array(iv.length + encryptedContent.byteLength);
            result.set(iv, 0);
            result.set(new Uint8Array(encryptedContent), iv.length);

            const encrypted = this.arrayBufferToBase64(result);
            console.log(`🔒 Message encrypted (${message.length} chars → ${encrypted.length} chars)`);
            
            return encrypted;
            
        } catch (error) {
            console.error('❌ Encryption failed:', error);
            throw error;
        }
    }

    /**
     * Decrypt a message from a room
     * @param {string} roomId - The room ID
     * @param {string} encryptedMessage - Base64 encoded encrypted message
     * @returns {string} Decrypted plaintext message
     */
    async decryptMessage(roomId, encryptedMessage) {
        if (!this.isInitialized) {
            await this.initialize();
        }

        try {
            // Get room key
            const roomKey = await this.getRoomKey(roomId);
            
            // Decode base64
            const encryptedData = this.base64ToArrayBuffer(encryptedMessage);
            
            // Extract IV (first 12 bytes) and ciphertext
            const iv = encryptedData.slice(0, 12);
            const ciphertext = encryptedData.slice(12);

            // Decrypt
            const decryptedContent = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                roomKey,
                ciphertext
            );

            const decrypted = new TextDecoder().decode(decryptedContent);
            console.log(`🔓 Message decrypted (${encryptedMessage.length} chars → ${decrypted.length} chars)`);
            
            return decrypted;
            
        } catch (error) {
            console.error('❌ Decryption failed:', error);
            return '[🔒 Encrypted message - unable to decrypt]';
        }
    }
    

    /**
     * Export user's keypair for backup
     * @returns {object} Keypair in JWK format
     */
    async exportKeys() {
        if (!this.isInitialized) {
            await this.initialize();
        }

        const publicKeyJwk = await crypto.subtle.exportKey('jwk', this.keyPair.publicKey);
        const privateKeyJwk = await crypto.subtle.exportKey('jwk', this.keyPair.privateKey);

        return {
            publicKey: publicKeyJwk,
            privateKey: privateKeyJwk,
            exportedAt: new Date().toISOString()
        };
    }

    /**
     * Import keypair from backup
     * @param {object} keys - Keypair in JWK format
     */
    async importKeys(keys) {
        try {
            this.keyPair = {
                publicKey: await crypto.subtle.importKey(
                    'jwk',
                    keys.publicKey,
                    {
                        name: 'RSA-OAEP',
                        hash: 'SHA-256',
                    },
                    true,
                    ['encrypt']
                ),
                privateKey: await crypto.subtle.importKey(
                    'jwk',
                    keys.privateKey,
                    {
                        name: 'RSA-OAEP',
                        hash: 'SHA-256',
                    },
                    true,
                    ['decrypt']
                )
            };

            // Store in localStorage
            localStorage.setItem('userKeyPair', JSON.stringify({
                publicKey: keys.publicKey,
                privateKey: keys.privateKey,
                importedAt: new Date().toISOString()
            }));

            this.isInitialized = true;
            console.log('✅ Keys imported successfully');
            
        } catch (error) {
            console.error('❌ Key import failed:', error);
            throw error;
        }
    }

    /**
     * Clear all encryption keys (logout/reset)
     */
    clearKeys() {
        this.keyPair = null;
        this.roomKeys.clear();
        this.isInitialized = false;
        this.initPromise = null;
        localStorage.removeItem('userKeyPair');
        console.log('🗑️ All encryption keys cleared');
    }

    // ==================== HELPER FUNCTIONS ====================

    /**
     * Convert ArrayBuffer to Base64 string
     */
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    /**
     * Convert Base64 string to ArrayBuffer
     */
    base64ToArrayBuffer(base64) {
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes;
    }

    /**
     * Get cookie value by name
     */
    getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }

    /**
     * Check if browser supports required crypto features
     */
    static isSupported() {
        return typeof crypto !== 'undefined' &&
               typeof crypto.subtle !== 'undefined' &&
               typeof crypto.getRandomValues !== 'undefined';
    }

    /**
     * Get encryption status info
     */
    getStatus() {
        return {
            initialized: this.isInitialized,
            hasKeyPair: this.keyPair !== null,
            roomKeysCount: this.roomKeys.size,
            browserSupported: E2EEManager.isSupported()
        };
    }
}

// ==================== GLOBAL INSTANCE ====================

// Create global instance
const e2eeManager = new E2EEManager();

// Check browser support on load
if (!E2EEManager.isSupported()) {
    console.error('❌ Web Crypto API not supported in this browser');
    console.error('Please use a modern browser (Chrome, Firefox, Safari, Edge)');
}

// Export for use in other scripts
if (typeof window !== 'undefined') {
    window.e2eeManager = e2eeManager;
    window.E2EEManager = E2EEManager;
}

console.log('📦 E2EE Library loaded');