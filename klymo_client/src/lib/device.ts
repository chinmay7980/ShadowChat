import FingerprintJS from '@fingerprintjs/fingerprintjs';

/**
 * Generates a unique device fingerprint hash with salt as per PRD Bucket A.
 */
export async function getDeviceFingerprint(): Promise<string> {
    const fp = await FingerprintJS.load();
    const result = await fp.get();
    const visitorId = result.visitorId;

    // Hash + Salt logic for Zero PII
    const salt = "anon_chat_v1_salt";
    const msgUint8 = new TextEncoder().encode(visitorId + salt);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    return hashHex;
}

/**
 * Handles device identity storage and daily limit logic.
 */
export const DeviceIdentity = {
    getStoredId: () => typeof window !== 'undefined' ? localStorage.getItem('anon_chat_device_id') : null,
    setStoredId: (id: string) => {
        if (typeof window !== 'undefined') localStorage.setItem('anon_chat_device_id', id);
    },

    getMatchCount: () => {
        if (typeof window === 'undefined') return 0;
        const data = localStorage.getItem('anon_chat_daily_stats');
        if (!data) return 0;
        try {
            const { count, date } = JSON.parse(data);
            const today = new Date().toDateString();
            return date === today ? count : 0;
        } catch (e) {
            return 0;
        }
    },

    incrementMatchCount: () => {
        if (typeof window === 'undefined') return;
        const today = new Date().toDateString();
        const current = DeviceIdentity.getMatchCount();
        localStorage.setItem('anon_chat_daily_stats', JSON.stringify({
            count: current + 1,
            date: today,
            last_active: Date.now()
        }));
    },

    isLimitReached: (limit: number = 100) => {
        return DeviceIdentity.getMatchCount() >= limit;
    }
};
