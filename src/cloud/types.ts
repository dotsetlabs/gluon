/**
 * Shared API types for Gluon Cloud
 * 
 * These types match the shared auth API used by both Axion and Gluon CLIs.
 */

/**
 * User information returned from authentication
 */
export interface User {
    id: string;
    email: string;
    name: string | null;
}

/**
 * Authentication tokens
 */
export interface AuthTokens {
    accessToken: string;
    refreshToken: string;
    expiresAt: number; // Unix timestamp
}

/**
 * Device Code Flow - Initial response
 */
export interface DeviceCodeResponse {
    deviceCode: string;
    userCode: string;
    verificationUri: string;
    expiresIn: number;
    interval: number;
}

/**
 * Device Code Flow - Poll response
 */
export interface DevicePollResponse {
    status: 'pending' | 'slow_down' | 'complete';
    user?: User;
    tokens?: AuthTokens;
}

/**
 * Token refresh response
 */
export interface RefreshResponse {
    accessToken: string;
    refreshToken: string;
    expiresAt: number;
}

/**
 * API error response
 */
export interface ApiError {
    code: string;
    message: string;
    details?: Record<string, unknown>;
}
