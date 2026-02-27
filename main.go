package main

import (
"bytes"
"context"
"crypto/hmac"
"crypto/rand"
"crypto/sha256"
"crypto/tls"
"database/sql"
"encoding/csv"
"encoding/hex"
"encoding/json"
"fmt"
"io"
"log"
mathrand "math/rand"
"net"
"net/http"
"os"
"os/signal"
"strconv"
"strings"
"sync"
"syscall"
"time"

"github.com/golang-jwt/jwt/v5"
_ "github.com/mattn/go-sqlite3"
"go.mau.fi/whatsmeow"
"go.mau.fi/whatsmeow/store/sqlstore"
"go.mau.fi/whatsmeow/types"
"go.mau.fi/whatsmeow/types/events"
waProto "go.mau.fi/whatsmeow/proto/waE2E"
waLog "go.mau.fi/whatsmeow/util/log"
"google.golang.org/protobuf/proto"
)

const serverVersion = "2.0.0"

var (
client            *whatsmeow.Client
systemLogs        []string
logMu             sync.Mutex
config            AutoConfig
pairAttempts      = make(map[string]time.Time)
pairMu            sync.Mutex
scheduledMessages []ScheduledMessage
scheduleMu        sync.Mutex
messageStats      MessageStats
statsMu           sync.Mutex
lastMessageTime   time.Time
messageMu         sync.Mutex
userAgents        []string
deviceFingerprint map[string]string
)

var (
clients   = make(map[string]*whatsmeow.Client)
clientsMu sync.RWMutex
)

var configMu sync.RWMutex

var (
linkedPhonesMu sync.RWMutex
linkedPhones   = make(map[string]bool)
)

var (
messageHistory []MessageLogEntry
historyMu      sync.Mutex
)

var serverStartTime = time.Now()

var jwtSecret []byte

var statsDB *sql.DB

var globalRateLimiter *ipRateLimiter

var adminWhitelistIPs []string
var adminWhitelistCIDRs []*net.IPNet

type AutoConfig struct {
Enabled            bool              `json:"enabled"`
Numbers            string            `json:"numbers"`
Message            string            `json:"message"`
ReplyEnable        bool              `json:"reply_enable"`
ReplyText          string            `json:"reply_text"`
Templates          []MessageTemplate `json:"templates"`
MaxRetries         int               `json:"max_retries"`
RetryDelay         int               `json:"retry_delay_seconds"`
SendDelay          int               `json:"send_delay_seconds"`
MinSendDelay       int               `json:"min_send_delay_seconds"`
MaxSendDelay       int               `json:"max_send_delay_seconds"`
DailySendLimit     int               `json:"daily_send_limit"`
HourlySendLimit    int               `json:"hourly_send_limit"`
RandomizeUserAgent bool              `json:"randomize_user_agent"`
SafeMode           bool              `json:"safe_mode"`
WebhookURL         string            `json:"webhook_url"`
WebhookSecret      string            `json:"webhook_secret"`
WebhookEnabled     bool              `json:"webhook_enabled"`
}

type MessageTemplate struct {
Name    string `json:"name"`
Content string `json:"content"`
}

type ScheduledMessage struct {
ID          string    `json:"id"`
Phone       string    `json:"phone"`
Message     string    `json:"message"`
ScheduledAt time.Time `json:"scheduled_at"`
Status      string    `json:"status"`
Attempts    int       `json:"attempts"`
}

type MessageStats struct {
TotalSent     int            `json:"total_sent"`
TotalFailed   int            `json:"total_failed"`
TotalReceived int            `json:"total_received"`
LastActivity  time.Time      `json:"last_activity"`
DailyCounts   map[string]int `json:"daily_counts"`
HourlyCounts  map[string]int `json:"hourly_counts"`
BanWarnings   int            `json:"ban_warnings"`
LastBanCheck  time.Time      `json:"last_ban_check"`
}

type APIResponse struct {
Success bool        `json:"success"`
Message string      `json:"message"`
Data    interface{} `json:"data,omitempty"`
Warning string      `json:"warning,omitempty"`
}

type MediaSendRequest struct {
Phone   string `json:"phone"`
URL     string `json:"url"`
Caption string `json:"caption"`
Type    string `json:"type"`
}

type DeviceInfo struct {
ID        string `json:"id"`
Connected bool   `json:"connected"`
JID       string `json:"jid"`
Phone     string `json:"phone"`
Name      string `json:"name"`
}

type MessageLogEntry struct {
ID             string     `json:"id"`
Direction      string     `json:"direction"`
Phone          string     `json:"phone"`
Message        string     `json:"message"`
Status         string     `json:"status"`
Timestamp      time.Time  `json:"timestamp"`
MessageID      string     `json:"message_id,omitempty"`
DeliveryStatus string     `json:"delivery_status,omitempty"`
DeliveredAt    *time.Time `json:"delivered_at,omitempty"`
ReadAt         *time.Time `json:"read_at,omitempty"`
}

type ipRateLimiter struct {
mu       sync.Mutex
requests map[string][]time.Time
limit    int
}

// APIKey represents an API key for authentication
type APIKey struct {
ID        string    `json:"id"`
Key       string    `json:"key"`
Name      string    `json:"name"`
Role      string    `json:"role"`
CreatedAt time.Time `json:"created_at"`
LastUsed  time.Time `json:"last_used,omitempty"`
Active    bool      `json:"active"`
}

// LoginAttempt tracks failed login attempts per IP
type LoginAttempt struct {
Count     int       `json:"count"`
LockedAt  time.Time `json:"locked_at,omitempty"`
LockUntil time.Time `json:"lock_until,omitempty"`
}

// BulkSendJob tracks a bulk CSV send operation
type BulkSendJob struct {
ID         string       `json:"id"`
Status     string       `json:"status"`
Total      int          `json:"total"`
Sent       int          `json:"sent"`
Failed     int          `json:"failed"`
Progress   int          `json:"progress"`
CreatedAt  time.Time    `json:"created_at"`
UpdatedAt  time.Time    `json:"updated_at"`
CancelChan chan struct{} `json:"-"`
PauseChan  chan bool     `json:"-"`
cancelOnce sync.Once    `json:"-"`
Paused     bool         `json:"paused"`
}

var (
apiKeys   []APIKey
apiKeysMu sync.RWMutex
)

var (
loginAttempts   = make(map[string]*LoginAttempt)
loginAttemptsMu sync.Mutex
)

var (
bulkJobs   []*BulkSendJob
bulkJobsMu sync.Mutex
)

func initSecurity() {
userAgents = []string{
"WhatsApp/2.23.20.0 Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
"WhatsApp/2.23.19.0 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
"WhatsApp/2.23.18.0 Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
"WhatsApp/2.23.17.0 Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36",
}
deviceFingerprint = map[string]string{
"platform":    "desktop",
"app_version": "2.23.20.0",
"os_version":  "macOS 12.6",
"device_id":   generateDeviceID(),
}
if messageStats.DailyCounts == nil {
messageStats.DailyCounts = make(map[string]int)
}
if messageStats.HourlyCounts == nil {
messageStats.HourlyCounts = make(map[string]int)
}
loadAPIKeys()
}

func loadAPIKeys() {
data, err := os.ReadFile("apikeys.json")
if err != nil {
return
}
apiKeysMu.Lock()
defer apiKeysMu.Unlock()
if err := json.Unmarshal(data, &apiKeys); err != nil {
addLog("Error loading apikeys.json: "+err.Error(), "ERROR")
}
}

func saveAPIKeys() {
apiKeysMu.RLock()
data, _ := json.MarshalIndent(apiKeys, "", "  ")
apiKeysMu.RUnlock()
if err := os.WriteFile("apikeys.json", data, 0600); err != nil {
addLog("Error saving apikeys.json: "+err.Error(), "ERROR")
}
go syncAPIKeysToSupabase()
}

func validateAPIKey(key string) *APIKey {
apiKeysMu.RLock()
idx := -1
for i, k := range apiKeys {
if k.Key == key && k.Active {
idx = i
break
}
}
apiKeysMu.RUnlock()
if idx < 0 {
return nil
}
apiKeysMu.Lock()
apiKeys[idx].LastUsed = time.Now()
result := apiKeys[idx]
apiKeysMu.Unlock()
go saveAPIKeys()
return &result
}

func recordFailedLogin(ip string) {
loginAttemptsMu.Lock()
defer loginAttemptsMu.Unlock()
a, ok := loginAttempts[ip]
if !ok {
a = &LoginAttempt{}
loginAttempts[ip] = a
}
a.Count++
if a.Count >= 10 {
a.LockedAt = time.Now()
a.LockUntil = time.Now().Add(2 * time.Hour)
} else if a.Count >= 5 {
a.LockedAt = time.Now()
a.LockUntil = time.Now().Add(30 * time.Minute)
}
}

func isIPLocked(ip string) bool {
loginAttemptsMu.Lock()
defer loginAttemptsMu.Unlock()
a, ok := loginAttempts[ip]
if !ok {
return false
}
if time.Now().Before(a.LockUntil) {
return true
}
// Reset count after lock period
if !a.LockUntil.IsZero() && time.Now().After(a.LockUntil) {
a.Count = 0
a.LockUntil = time.Time{}
a.LockedAt = time.Time{}
loginAttempts[ip] = a
}
return false
}

func isIPWhitelisted(ip string) bool {
	if len(adminWhitelistIPs) == 0 && len(adminWhitelistCIDRs) == 0 {
		return true
	}
	for _, entry := range adminWhitelistIPs {
		if entry == ip {
			return true
		}
	}
	parsed := net.ParseIP(ip)
	if parsed != nil {
		for _, cidr := range adminWhitelistCIDRs {
			if cidr.Contains(parsed) {
				return true
			}
		}
	}
	return false
}

func generateDeviceID() string {
bytes := make([]byte, 16)
rand.Read(bytes)
return fmt.Sprintf("%x-%x-%x-%x-%x", bytes[0:4], bytes[4:6], bytes[6:8], bytes[8:10], bytes[10:16])
}

func getRandomUserAgent() string {
if len(userAgents) == 0 {
return "WhatsApp/2.23.20.0"
}
return userAgents[mathrand.Intn(len(userAgents))]
}

func addLog(msg string, level ...string) {
logMu.Lock()
defer logMu.Unlock()
logLevel := "INFO"
if len(level) > 0 {
logLevel = level[0]
}
timestamp := time.Now().Format("15:04:05")
logEntry := fmt.Sprintf("[%s] [%s] %s", timestamp, logLevel, msg)
systemLogs = append([]string{logEntry}, systemLogs...)
if len(systemLogs) > 200 {
systemLogs = systemLogs[:200]
}
if len(level) > 0 && level[0] == "SECURITY" {
fmt.Printf("\U0001f512 SECURITY: %s\n", logEntry)
} else {
fmt.Println(logEntry)
}
}

func isSendingSafe(phoneNumber string) (bool, string) {
messageMu.Lock()
defer messageMu.Unlock()

configMu.RLock()
dailyLimit := config.DailySendLimit
hourlyLimit := config.HourlySendLimit
minSendDelay := config.MinSendDelay
safeMode := config.SafeMode
configMu.RUnlock()

now := time.Now()
today := now.Format("2006-01-02")
hour := now.Format("2006-01-02-15")
if dailyLimit > 0 && messageStats.DailyCounts[today] >= dailyLimit {
return false, fmt.Sprintf("Daily limit reached (%d messages)", dailyLimit)
}
if hourlyLimit > 0 && messageStats.HourlyCounts[hour] >= hourlyLimit {
return false, fmt.Sprintf("Hourly limit reached (%d messages)", hourlyLimit)
}
minDelay := time.Duration(minSendDelay) * time.Second
if minSendDelay > 0 && time.Since(lastMessageTime) < minDelay {
return false, fmt.Sprintf("Too fast sending (min delay: %ds)", minSendDelay)
}
if safeMode {
if messageStats.DailyCounts[today] >= 50 {
return false, "Safe mode: Daily limit of 50 messages reached"
}
if messageStats.HourlyCounts[hour] >= 10 {
return false, "Safe mode: Hourly limit of 10 messages reached"
}
}
return true, ""
}

func calculateSmartDelay() time.Duration {
configMu.RLock()
minDelay := config.MinSendDelay
maxDelay := config.MaxSendDelay
configMu.RUnlock()
if minDelay == 0 {
minDelay = 3
}
if maxDelay == 0 {
maxDelay = 8
}
if maxDelay <= minDelay {
maxDelay = minDelay + 5
}
baseDelay := minDelay + mathrand.Intn(maxDelay-minDelay+1)
variation := int(float64(baseDelay) * 0.2)
if variation < 1 {
variation = 1
}
finalDelay := baseDelay + mathrand.Intn(variation*2+1) - variation
if finalDelay < minDelay {
finalDelay = minDelay
}
return time.Duration(finalDelay) * time.Second
}

func updateMessageStats(sent bool) {
statsMu.Lock()
defer statsMu.Unlock()
now := time.Now()
today := now.Format("2006-01-02")
hour := now.Format("2006-01-02-15")
if sent {
messageStats.TotalSent++
messageStats.DailyCounts[today]++
messageStats.HourlyCounts[hour]++
} else {
messageStats.TotalFailed++
}
messageStats.LastActivity = now
cutoff := now.AddDate(0, 0, -7).Format("2006-01-02")
for date := range messageStats.DailyCounts {
if date < cutoff {
delete(messageStats.DailyCounts, date)
}
}
cutoffHour := now.Add(-24 * time.Hour).Format("2006-01-02-15")
for hourKey := range messageStats.HourlyCounts {
if hourKey < cutoffHour {
delete(messageStats.HourlyCounts, hourKey)
}
}
}

func loadConfig() {
data, err := os.ReadFile("config.json")
if err != nil {
configMu.Lock()
config = AutoConfig{
Enabled:            false,
Numbers:            "",
Message:            "",
ReplyEnable:        false,
ReplyText:          "",
Templates:          []MessageTemplate{},
MaxRetries:         2,
RetryDelay:         10,
SendDelay:          5,
MinSendDelay:       3,
MaxSendDelay:       12,
DailySendLimit:     100,
HourlySendLimit:    20,
RandomizeUserAgent: true,
SafeMode:           true,
}
configMu.Unlock()
saveConfig()
addLog("\U0001f512 Security-enhanced configuration created", "SECURITY")
return
}
var newConfig AutoConfig
if err := json.Unmarshal(data, &newConfig); err != nil {
addLog("Error loading config: "+err.Error(), "ERROR")
return
}
if newConfig.MinSendDelay == 0 {
newConfig.MinSendDelay = 3
}
if newConfig.MaxSendDelay == 0 {
newConfig.MaxSendDelay = 12
}
if newConfig.DailySendLimit == 0 {
newConfig.DailySendLimit = 100
}
if newConfig.HourlySendLimit == 0 {
newConfig.HourlySendLimit = 20
}
configMu.Lock()
config = newConfig
configMu.Unlock()
}

func saveConfig() {
configMu.RLock()
data, err := json.MarshalIndent(config, "", "  ")
configMu.RUnlock()
if err != nil {
addLog("Error saving config: "+err.Error(), "ERROR")
return
}
if err := os.WriteFile("config.json", data, 0644); err != nil {
addLog("Error saving config: "+err.Error(), "ERROR")
}
}

func loadLinkedPhones() {
data, err := os.ReadFile("linked_phones.json")
if err != nil {
if !os.IsNotExist(err) {
addLog("Error loading linked phones: "+err.Error(), "ERROR")
}
return
}
var phones map[string]bool
if err := json.Unmarshal(data, &phones); err != nil {
addLog("Error loading linked phones: "+err.Error(), "ERROR")
return
}
linkedPhonesMu.Lock()
linkedPhones = phones
linkedPhonesMu.Unlock()
}

func saveLinkedPhones() {
linkedPhonesMu.RLock()
data, err := json.MarshalIndent(linkedPhones, "", "  ")
linkedPhonesMu.RUnlock()
if err != nil {
addLog("Error saving linked phones: "+err.Error(), "ERROR")
return
}
if err := os.WriteFile("linked_phones.json", data, 0600); err != nil {
addLog("Error saving linked phones: "+err.Error(), "ERROR")
}
}

func rateLimitPairing(phone string) bool {
pairMu.Lock()
defer pairMu.Unlock()
if lastAttempt, exists := pairAttempts[phone]; exists {
if time.Since(lastAttempt) < 60*time.Second {
return false
}
}
pairAttempts[phone] = time.Now()
return true
}

func initJWT() {
secret := os.Getenv("JWT_SECRET")
if secret == "" {
b := make([]byte, 32)
rand.Read(b)
secret = hex.EncodeToString(b)
addLog("\u26a0\ufe0f JWT_SECRET not set - generated random secret (tokens won't survive restart)", "SECURITY")
}
jwtSecret = []byte(secret)
}

func jwtAuth(tokenStr string) bool {
token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
}
return jwtSecret, nil
})
return err == nil && token.Valid
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
return func(w http.ResponseWriter, r *http.Request) {
ip := r.RemoteAddr
if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
ip = strings.TrimSpace(strings.SplitN(fwd, ",", 2)[0])
} else if host, _, err := net.SplitHostPort(ip); err == nil {
ip = host
}
// IP whitelist check (must be first)
if !isIPWhitelisted(ip) {
addLog(fmt.Sprintf("Blocked request from non-whitelisted IP: %s", ip), "SECURITY")
w.Header().Set("Content-Type", "application/json")
w.WriteHeader(http.StatusForbidden)
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Access denied: IP not whitelisted"})
return
}
// API key via X-API-Key header (checked before JWT/Basic, bypasses lockout for valid keys)
if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
if k := validateAPIKey(apiKey); k != nil {
next.ServeHTTP(w, r)
return
}
addLog(fmt.Sprintf("Invalid API key attempt from: %s", r.RemoteAddr), "SECURITY")
recordFailedLogin(ip)
w.Header().Set("Content-Type", "application/json")
w.WriteHeader(http.StatusUnauthorized)
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Invalid API key"})
return
}
// JWT token (bypasses lockout for valid tokens)
authHeader := r.Header.Get("Authorization")
if strings.HasPrefix(authHeader, "Bearer ") {
tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
if jwtAuth(tokenStr) {
next.ServeHTTP(w, r)
return
}
}
// Check IP lockout before Basic Auth
if isIPLocked(ip) {
w.Header().Set("Content-Type", "application/json")
w.WriteHeader(http.StatusForbidden)
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "IP temporarily locked due to too many failed attempts"})
return
}
user, pass, ok := r.BasicAuth()
adminUser := os.Getenv("ADMIN_USER")
adminPass := os.Getenv("ADMIN_PASS")
if adminUser == "" {
adminUser = "admin"
}
if adminPass == "" {
adminPass = "admin123"
}
if !ok || user != adminUser || pass != adminPass {
addLog(fmt.Sprintf("Failed login attempt from: %s", r.RemoteAddr), "SECURITY")
recordFailedLogin(ip)
w.Header().Set("WWW-Authenticate", `Basic realm="Restricted Area"`)
http.Error(w, "Unauthorized Access", http.StatusUnauthorized)
return
}
next.ServeHTTP(w, r)
}
}

func newIPRateLimiter(limit int) *ipRateLimiter {
rl := &ipRateLimiter{
requests: make(map[string][]time.Time),
limit:    limit,
}
go rl.cleanupLoop()
return rl
}

func (rl *ipRateLimiter) Allow(ip string) bool {
rl.mu.Lock()
defer rl.mu.Unlock()
now := time.Now()
windowStart := now.Add(-time.Minute)
reqs := rl.requests[ip]
valid := make([]time.Time, 0, len(reqs)+1)
for _, t := range reqs {
if t.After(windowStart) {
valid = append(valid, t)
}
}
valid = append(valid, now)
rl.requests[ip] = valid
return len(valid) <= rl.limit
}

func (rl *ipRateLimiter) cleanupLoop() {
for range time.Tick(5 * time.Minute) {
rl.mu.Lock()
cutoff := time.Now().Add(-time.Minute)
for ip, reqs := range rl.requests {
valid := make([]time.Time, 0, len(reqs))
for _, t := range reqs {
if t.After(cutoff) {
valid = append(valid, t)
}
}
if len(valid) == 0 {
delete(rl.requests, ip)
} else {
rl.requests[ip] = valid
}
}
rl.mu.Unlock()
}
}

func rateLimitMiddleware(next http.Handler) http.Handler {
return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
ip := r.RemoteAddr
if idx := strings.LastIndex(ip, ":"); idx != -1 {
ip = ip[:idx]
}
if !globalRateLimiter.Allow(ip) {
w.Header().Set("Content-Type", "application/json")
w.WriteHeader(http.StatusTooManyRequests)
json.NewEncoder(w).Encode(APIResponse{
Success: false,
Message: "Rate limit exceeded. Please slow down.",
})
return
}
next.ServeHTTP(w, r)
})
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
w.Header().Set("X-Content-Type-Options", "nosniff")
w.Header().Set("X-Frame-Options", "DENY")
w.Header().Set("X-XSS-Protection", "1; mode=block")
w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
next.ServeHTTP(w, r)
})
}

func initStatsDB() {
db, err := sql.Open("sqlite3", "file:stats.db?_foreign_keys=on")
if err != nil {
addLog("Failed to open stats.db: "+err.Error(), "ERROR")
return
}
_, err = db.Exec(`CREATE TABLE IF NOT EXISTS daily_stats (
date TEXT PRIMARY KEY,
sent INTEGER DEFAULT 0,
failed INTEGER DEFAULT 0,
received INTEGER DEFAULT 0
)`)
if err != nil {
addLog("Failed to create daily_stats table: "+err.Error(), "ERROR")
db.Close()
return
}
statsDB = db
rows, err := db.Query(`SELECT date, sent, failed, received FROM daily_stats WHERE date >= ? ORDER BY date DESC`,
time.Now().AddDate(0, 0, -7).Format("2006-01-02"))
if err == nil {
defer rows.Close()
statsMu.Lock()
for rows.Next() {
var date string
var sent, failed, received int
if err := rows.Scan(&date, &sent, &failed, &received); err == nil {
messageStats.DailyCounts[date] += sent
messageStats.TotalSent += sent
messageStats.TotalFailed += failed
messageStats.TotalReceived += received
}
}
statsMu.Unlock()
}
addLog("\U0001f4ca Stats database initialized", "INFO")
}

func persistStats() {
if statsDB == nil {
return
}
statsMu.Lock()
today := time.Now().Format("2006-01-02")
sent := messageStats.DailyCounts[today]
totalSent := messageStats.TotalSent
failed := messageStats.TotalFailed
received := messageStats.TotalReceived
statsMu.Unlock()
_, err := statsDB.Exec(`INSERT INTO daily_stats (date, sent, failed, received) VALUES (?, ?, ?, ?)
ON CONFLICT(date) DO UPDATE SET sent=excluded.sent, failed=excluded.failed, received=excluded.received`,
today, sent, failed, received)
if err != nil {
addLog("Failed to persist stats: "+err.Error(), "ERROR")
}
go writeToSupabaseUpsert("stats", map[string]interface{}{
"id":                1,
"messages_sent":     totalSent,
"messages_received": received,
"active_devices":    countConnectedDevices(),
"updated_at":        time.Now().UTC().Format(time.RFC3339),
})
}

func addToHistory(direction, phone, message, status string, msgID ...string) {
historyMu.Lock()
defer historyMu.Unlock()
idBytes := make([]byte, 4)
rand.Read(idBytes)
entry := MessageLogEntry{
ID:             fmt.Sprintf("%x", idBytes),
Direction:      direction,
Phone:          phone,
Message:        message,
Status:         status,
Timestamp:      time.Now(),
DeliveryStatus: "pending",
}
if len(msgID) > 0 && msgID[0] != "" {
entry.MessageID = msgID[0]
}
messageHistory = append([]MessageLogEntry{entry}, messageHistory...)
if len(messageHistory) > 1000 {
messageHistory = messageHistory[:1000]
}
}

// supabaseAllowedTables is the set of tables that may be written to via Supabase REST.
var supabaseAllowedTables = map[string]bool{
"stats": true, "message_history": true, "devices": true,
"api_keys": true, "bulk_jobs": true, "scheduled_messages": true,
}

// supabaseDeleteAllFilter is a Supabase filter that matches every row (used for bulk deletes).
const supabaseDeleteAllFilter = "id=neq.00000000-0000-0000-0000-000000000000"

func writeToSupabase(table string, data map[string]interface{}) {
if !supabaseAllowedTables[table] {
return
}
supabaseURL := os.Getenv("SUPABASE_URL")
serviceKey := os.Getenv("SUPABASE_SERVICE_KEY")
if supabaseURL == "" || serviceKey == "" {
return
}
body, err := json.Marshal(data)
if err != nil {
return
}
req, err := http.NewRequest("POST", supabaseURL+"/rest/v1/"+table, bytes.NewBuffer(body))
if err != nil {
return
}
req.Header.Set("Authorization", "Bearer "+serviceKey)
req.Header.Set("apikey", serviceKey)
req.Header.Set("Content-Type", "application/json")
resp, err := http.DefaultClient.Do(req)
if err != nil {
return
}
defer resp.Body.Close()
io.Copy(io.Discard, resp.Body)
}

func writeToSupabaseUpsert(table string, data map[string]interface{}) {
if !supabaseAllowedTables[table] {
return
}
supabaseURL := os.Getenv("SUPABASE_URL")
serviceKey := os.Getenv("SUPABASE_SERVICE_KEY")
if supabaseURL == "" || serviceKey == "" {
return
}
body, err := json.Marshal(data)
if err != nil {
return
}
req, err := http.NewRequest("POST", supabaseURL+"/rest/v1/"+table, bytes.NewBuffer(body))
if err != nil {
return
}
req.Header.Set("Authorization", "Bearer "+serviceKey)
req.Header.Set("apikey", serviceKey)
req.Header.Set("Content-Type", "application/json")
req.Header.Set("Prefer", "resolution=merge-duplicates,return=minimal")
resp, err := http.DefaultClient.Do(req)
if err != nil {
return
}
defer resp.Body.Close()
io.Copy(io.Discard, resp.Body)
}

func countConnectedDevices() int {
clientsMu.RLock()
defer clientsMu.RUnlock()
count := 0
for _, c := range clients {
if c != nil && c.IsConnected() {
count++
}
}
return count
}

func syncAPIKeysToSupabase() {
supabaseURL := os.Getenv("SUPABASE_URL")
serviceKey := os.Getenv("SUPABASE_SERVICE_KEY")
if supabaseURL == "" || serviceKey == "" {
return
}
// Delete all existing rows then re-insert active keys so Supabase stays consistent.
req, err := http.NewRequest("DELETE", supabaseURL+"/rest/v1/api_keys?"+supabaseDeleteAllFilter, nil)
if err != nil {
return
}
req.Header.Set("Authorization", "Bearer "+serviceKey)
req.Header.Set("apikey", serviceKey)
if resp, err := http.DefaultClient.Do(req); err == nil {
defer resp.Body.Close()
io.Copy(io.Discard, resp.Body)
}
apiKeysMu.RLock()
keys := make([]APIKey, len(apiKeys))
copy(keys, apiKeys)
apiKeysMu.RUnlock()
for _, k := range keys {
if !k.Active {
continue
}
writeToSupabase("api_keys", map[string]interface{}{
"name":       k.Name,
"key":        k.Key,
"created_at": k.CreatedAt.UTC().Format(time.RFC3339),
})
}
}


func fireWebhook(payload map[string]interface{}) {
configMu.RLock()
webhookURL := config.WebhookURL
webhookSecret := config.WebhookSecret
configMu.RUnlock()
if webhookURL == "" {
return
}
body, err := json.Marshal(payload)
if err != nil {
addLog("Webhook marshal error: "+err.Error(), "ERROR")
return
}
for attempt := 1; attempt <= 3; attempt++ {
httpClient := &http.Client{Timeout: 10 * time.Second}
req, err := http.NewRequest(http.MethodPost, webhookURL, strings.NewReader(string(body)))
if err != nil {
addLog("Webhook request error: "+err.Error(), "ERROR")
return
}
req.Header.Set("Content-Type", "application/json")
if webhookSecret != "" {
mac := hmac.New(sha256.New, []byte(webhookSecret))
mac.Write(body)
sig := hex.EncodeToString(mac.Sum(nil))
req.Header.Set("X-Webhook-Signature", "sha256="+sig)
}
resp, err := httpClient.Do(req)
if err != nil {
addLog(fmt.Sprintf("Webhook attempt %d failed: %v", attempt, err), "WARN")
if attempt < 3 {
time.Sleep(2 * time.Second)
}
continue
}
resp.Body.Close()
addLog(fmt.Sprintf("Webhook fired successfully (status %d)", resp.StatusCode))
return
}
addLog("Webhook failed after 3 attempts", "ERROR")
}

func eventHandler(evt interface{}) {
defer func() {
if r := recover(); r != nil {
addLog(fmt.Sprintf("Event handler panic: %v", r), "ERROR")
}
}()

switch v := evt.(type) {
case *events.Message:
if !v.Info.IsFromMe {
sender := "Unknown"
if v.Info.Sender.User != "" {
sender = v.Info.Sender.User
}
statsMu.Lock()
messageStats.TotalReceived++
messageStats.LastActivity = time.Now()
statsMu.Unlock()
addLog(fmt.Sprintf("\U0001f4e9 Message received from: %s", sender))

msgText := v.Message.GetConversation()
if msgText == "" {
if ext := v.Message.GetExtendedTextMessage(); ext != nil {
msgText = ext.GetText()
}
}

addToHistory("received", sender, msgText, "success")

configMu.RLock()
webhookEnabled := config.WebhookEnabled
webhookURL := config.WebhookURL
replyEnable := config.ReplyEnable
replyText := config.ReplyText
configMu.RUnlock()

if webhookEnabled && webhookURL != "" {
go fireWebhook(map[string]interface{}{
"event":     "message_received",
"sender":    sender,
"message":   msgText,
"timestamp": time.Now().UTC().Format(time.RFC3339),
})
}

if !v.Info.IsGroup && replyEnable && replyText != "" {
go sendSecureAutoReply(v.Info.Sender, replyText, sender)
}
}
case *events.Connected:
addLog("\U0001f7e2 Securely connected to WhatsApp", "SECURITY")
phone := ""
if client != nil && client.Store != nil && client.Store.ID != nil {
phone = client.Store.ID.User
}
if phone != "" {
linkedPhonesMu.Lock()
linkedPhones[phone] = true
linkedPhonesMu.Unlock()
saveLinkedPhones()
}
go writeToSupabaseUpsert("devices", map[string]interface{}{
"id":        "default",
"name":      "WhatsApp Device",
"phone":     phone,
"status":    "connected",
"last_seen": time.Now().UTC().Format(time.RFC3339),
})
go persistStats()
go startSecureAutoSend()
case *events.PairSuccess:
addLog("✅ Device securely linked with enhanced protection!", "SECURITY")
// Auto-send will be started in the Connected event handler above.
case *events.LoggedOut:
addLog("\U0001f534 Device logged out", "SECURITY")
if client != nil && client.Store != nil && client.Store.ID != nil {
phone := client.Store.ID.User
linkedPhonesMu.Lock()
delete(linkedPhones, phone)
linkedPhonesMu.Unlock()
saveLinkedPhones()
}
go writeToSupabaseUpsert("devices", map[string]interface{}{
"id":        "default",
"status":    "logged_out",
"last_seen": time.Now().UTC().Format(time.RFC3339),
})
case *events.Disconnected:
addLog("\u26a0\ufe0f Connection lost, implementing secure reconnection...", "WARN")
go writeToSupabaseUpsert("devices", map[string]interface{}{
"id":        "default",
"status":    "disconnected",
"last_seen": time.Now().UTC().Format(time.RFC3339),
})
statsMu.Lock()
messageStats.BanWarnings++
banWarnings := messageStats.BanWarnings
statsMu.Unlock()
if banWarnings > 3 {
addLog("\U0001f6a8 Multiple disconnections detected - possible ban warning!", "SECURITY")
}
case *events.StreamError:
addLog("\U0001f6a8 Stream error detected - possible security issue", "SECURITY")
statsMu.Lock()
messageStats.BanWarnings++
statsMu.Unlock()
case *events.Receipt:
if v.Type == events.ReceiptTypeDelivered || v.Type == events.ReceiptTypeRead {
now := time.Now()
historyMu.Lock()
for i := range messageHistory {
for _, id := range v.MessageIDs {
if messageHistory[i].MessageID == id {
if v.Type == events.ReceiptTypeDelivered {
messageHistory[i].DeliveryStatus = "delivered"
messageHistory[i].DeliveredAt = &now
} else if v.Type == events.ReceiptTypeRead {
messageHistory[i].DeliveryStatus = "read"
messageHistory[i].ReadAt = &now
}
}
}
}
historyMu.Unlock()
}
}
}

func sendSecureAutoReply(sender types.JID, replyText, senderUser string) {
defer func() {
if r := recover(); r != nil {
addLog(fmt.Sprintf("Auto-reply panic: %v", r), "ERROR")
}
}()
if safe, reason := isSendingSafe(sender.User); !safe {
addLog(fmt.Sprintf("\U0001f512 Auto-reply blocked for %s: %s", senderUser, reason), "SECURITY")
return
}
replyDelay := time.Duration(1+mathrand.Intn(4)) * time.Second
time.Sleep(replyDelay)
configMu.RLock()
maxRetries := config.MaxRetries
retryDelay := time.Duration(config.RetryDelay) * time.Second
configMu.RUnlock()
for attempt := 1; attempt <= maxRetries; attempt++ {
ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
if attempt == 1 {
typingTime := time.Duration(len(replyText)/10+1) * time.Second
if typingTime > 5*time.Second {
typingTime = 5 * time.Second
}
time.Sleep(typingTime)
}
msg := &waProto.Message{Conversation: proto.String(replyText)}
if _, err := client.SendMessage(ctx, sender, msg); err != nil {
cancel()
addLog(fmt.Sprintf("\u274c Auto-reply attempt %d failed to %s: %v", attempt, senderUser, err), "WARN")
if attempt < maxRetries {
time.Sleep(retryDelay)
continue
}
updateMessageStats(false)
} else {
cancel()
addLog("\U0001f916 Secure auto-reply sent to: " + senderUser)
updateMessageStats(true)
messageMu.Lock()
lastMessageTime = time.Now()
messageMu.Unlock()
break
}
}
}

func startSecureAutoSend() {
configMu.RLock()
enabled := config.Enabled
message := config.Message
numbers := config.Numbers
configMu.RUnlock()
if !enabled || message == "" || numbers == "" {
return
}
addLog("\u23f3 Starting secure auto-send with anti-ban protection...", "SECURITY")
initialDelay := time.Duration(30+mathrand.Intn(60)) * time.Second
addLog(fmt.Sprintf("\U0001f512 Waiting %v before starting (security measure)", initialDelay), "SECURITY")
time.Sleep(initialDelay)
rawNumbers := strings.FieldsFunc(numbers, func(r rune) bool {
return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == ';'
})
successCount := 0
failCount := 0
skippedCount := 0
for i, num := range rawNumbers {
num = strings.TrimSpace(num)
if num == "" {
continue
}
num = strings.ReplaceAll(num, "+", "")
num = strings.ReplaceAll(num, "-", "")
num = strings.ReplaceAll(num, " ", "")
if len(num) < 7 {
addLog(fmt.Sprintf("\u26a0\ufe0f Skipping invalid number: %s", num), "WARN")
skippedCount++
continue
}
if len(num) == 10 && !strings.HasPrefix(num, "91") {
num = "91" + num
}
if safe, reason := isSendingSafe(num); !safe {
addLog(fmt.Sprintf("\U0001f512 Skipping %s: %s", num, reason), "SECURITY")
skippedCount++
continue
}
addLog(fmt.Sprintf("\U0001f4e4 Securely sending to %s (%d/%d)", num, i+1, len(rawNumbers)))
success := sendSecureMessage(num, message)
if success {
successCount++
} else {
failCount++
}
delay := calculateSmartDelay()
addLog(fmt.Sprintf("\u23f1\ufe0f Smart delay: %v", delay))
time.Sleep(delay)
if failCount > 5 && successCount == 0 {
addLog("\U0001f6a8 Too many failures detected - stopping for security", "SECURITY")
break
}
}
addLog(fmt.Sprintf("\u2705 Secure auto-send complete! Success: %d, Failed: %d, Skipped: %d",
successCount, failCount, skippedCount), "SECURITY")
}

func sendSecureMessage(phone, message string) bool {
return sendSecureMessageWithClient(phone, message, client)
}

func sendSecureMessageWithClient(phone, message string, c *whatsmeow.Client) bool {
if c == nil || !c.IsConnected() {
addLog(fmt.Sprintf("⚠️ Cannot send to %s: client is nil or disconnected", phone), "WARN")
return false
}
targetJID := types.NewJID(phone, "s.whatsapp.net")
msg := &waProto.Message{Conversation: proto.String(message)}
configMu.RLock()
maxRetries := config.MaxRetries
retryDelay := time.Duration(config.RetryDelay) * time.Second
randomizeUA := config.RandomizeUserAgent
configMu.RUnlock()
if safe, reason := isSendingSafe(phone); !safe {
addLog(fmt.Sprintf("\U0001f512 Send blocked to %s: %s", phone, reason), "SECURITY")
return false
}
for attempt := 1; attempt <= maxRetries; attempt++ {
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
if randomizeUA {
userAgent := getRandomUserAgent()
addLog(fmt.Sprintf("\U0001f504 Using user agent: %s", userAgent), "SECURITY")
}
resp, err := c.SendMessage(ctx, targetJID, msg)
if err != nil {
cancel()
addLog(fmt.Sprintf("\u274c Secure send attempt %d to %s failed: %v", attempt, phone, err), "WARN")
if strings.Contains(strings.ToLower(err.Error()), "banned") ||
strings.Contains(strings.ToLower(err.Error()), "restricted") ||
strings.Contains(strings.ToLower(err.Error()), "rate limit") {
addLog("\U0001f6a8 BAN WARNING: Detected ban-related error!", "SECURITY")
messageStats.BanWarnings++
addToHistory("sent", phone, message, "failed")
go writeToSupabase("message_history", map[string]interface{}{
"direction": "sent",
"phone":     phone,
"message":   message,
"status":    "failed",
})
return false
}
if attempt < maxRetries {
backoffDelay := retryDelay * time.Duration(attempt)
time.Sleep(backoffDelay)
continue
}
updateMessageStats(false)
addToHistory("sent", phone, message, "failed")
go writeToSupabase("message_history", map[string]interface{}{
"direction": "sent",
"phone":     phone,
"message":   message,
"status":    "failed",
})
return false
} else {
cancel()
addLog(fmt.Sprintf("\u2709\ufe0f Message securely sent to: %s", phone))
updateMessageStats(true)
addToHistory("sent", phone, message, "success", resp.ID)
go writeToSupabase("message_history", map[string]interface{}{
"direction": "sent",
"phone":     phone,
"message":   message,
"status":    "sent",
})
go persistStats()
messageMu.Lock()
lastMessageTime = time.Now()
messageMu.Unlock()
return true
}
}
addToHistory("sent", phone, message, "failed")
go writeToSupabase("message_history", map[string]interface{}{
"direction": "sent",
"phone":     phone,
"message":   message,
"status":    "failed",
})
return false
}

func main() {
initSecurity()
loadConfig()
loadLinkedPhones()
if os.Getenv("ADMIN_USER") == "" || os.Getenv("ADMIN_PASS") == "" {
addLog("\u26a0\ufe0f WARNING: Using default admin credentials! Set ADMIN_USER and ADMIN_PASS env vars.", "SECURITY")
}
initJWT()
initStatsDB()
rateLimit := 60
if v := os.Getenv("RATE_LIMIT_RPM"); v != "" {
if n, err := strconv.Atoi(v); err == nil && n > 0 {
rateLimit = n
}
}
globalRateLimiter = newIPRateLimiter(rateLimit)
if wlEnv := os.Getenv("ADMIN_WHITELIST_IPS"); wlEnv != "" {
for _, entry := range strings.Split(wlEnv, ",") {
entry = strings.TrimSpace(entry)
if entry == "" {
continue
}
if strings.Contains(entry, "/") {
if _, cidr, err := net.ParseCIDR(entry); err == nil {
adminWhitelistCIDRs = append(adminWhitelistCIDRs, cidr)
}
} else {
adminWhitelistIPs = append(adminWhitelistIPs, entry)
}
}
addLog(fmt.Sprintf("🔒 IP whitelist enabled: %d IPs, %d CIDRs", len(adminWhitelistIPs), len(adminWhitelistCIDRs)), "SECURITY")
}
addLog("\U0001f680 SECURE WhatsApp Automation Server Started!", "SECURITY")
addLog("\U0001f512 Anti-ban protection: ENABLED", "SECURITY")
addLog("\U0001f6e1\ufe0f Security monitoring: ACTIVE", "SECURITY")
dbLog := waLog.Stdout("Database", "ERROR", true)
container, err := sqlstore.New(context.Background(), "sqlite3", "file:session.db?_foreign_keys=on", dbLog)
if err != nil {
log.Fatalf("Failed to connect to database: %v", err)
}
deviceStore, err := container.GetFirstDevice(context.Background())
if err != nil {
log.Fatalf("Failed to get device store: %v", err)
}
clientLog := waLog.Stdout("Client", "ERROR", true)
client = whatsmeow.NewClient(deviceStore, clientLog)
client.EnableAutoReconnect = true
client.AutoTrustIdentity = false
client.AddEventHandler(eventHandler)
clientsMu.Lock()
clients["default"] = client
clientsMu.Unlock()
go secureMessageScheduler()
go func() {
ticker := time.NewTicker(1 * time.Minute)
defer ticker.Stop()
for range ticker.C {
persistStats()
}
}()
http.HandleFunc("/", handleIndex)
http.HandleFunc("/pair", handleSecurePair)
http.HandleFunc("/is-linked", handleIsLinked)
http.HandleFunc("/auth/login", handleLogin)
http.HandleFunc("/health", handleHealth)
http.HandleFunc("/admin", authMiddleware(handleAdmin))
http.HandleFunc("/api/info", authMiddleware(handleApiInfo))
http.HandleFunc("/api/config", authMiddleware(handleSecureConfig))
http.HandleFunc("/api/logs", authMiddleware(handleLogs))
http.HandleFunc("/api/stats", authMiddleware(handleStatsWithDelete))
http.HandleFunc("/api/security", authMiddleware(handleSecurityStatus))
http.HandleFunc("/api/schedule", authMiddleware(handleSchedule))
http.HandleFunc("/api/devices", authMiddleware(handleDevices))
http.HandleFunc("/api/webhook/test", authMiddleware(handleWebhookTest))
http.HandleFunc("/api/history", authMiddleware(handleHistory))
http.HandleFunc("/logout", authMiddleware(handleLogout))
http.HandleFunc("/send", authMiddleware(handleSecureSend))
http.HandleFunc("/send/media", authMiddleware(handleSendMedia))
http.HandleFunc("/api/keys", authMiddleware(handleAPIKeys))
http.HandleFunc("/api/security/lockouts", authMiddleware(handleLockouts))
http.HandleFunc("/api/bulk-send", authMiddleware(handleBulkSend))
http.HandleFunc("/api/bulk-send/jobs", authMiddleware(handleBulkSendJobs))
http.HandleFunc("/api/bulk-send/jobs/cancel", authMiddleware(handleBulkJobCancel))
http.HandleFunc("/api/bulk-send/jobs/pause", authMiddleware(handleBulkJobPause))
http.HandleFunc("/api/bulk-send/jobs/resume", authMiddleware(handleBulkJobResume))
http.HandleFunc("/api/delivery", authMiddleware(handleDelivery))
http.HandleFunc("/api/restart", authMiddleware(handleRestart))
http.HandleFunc("/api/devices/disconnect-all", authMiddleware(handleDisconnectAll))
http.HandleFunc("/api/automation", authMiddleware(handleAutomation))
http.HandleFunc("/api/restore", authMiddleware(handleRestore))
port := os.Getenv("PORT")
if port == "" {
port = "8080"
}
srv := &http.Server{
Addr:    ":" + port,
Handler: rateLimitMiddleware(securityHeadersMiddleware(http.DefaultServeMux)),
}
tlsCert := os.Getenv("TLS_CERT_FILE")
tlsKey := os.Getenv("TLS_KEY_FILE")
go func() {
addLog(fmt.Sprintf("\U0001f310 Secure server running on port %s", port), "SECURITY")
var serveErr error
if tlsCert != "" && tlsKey != "" {
srv.TLSConfig = &tls.Config{
MinVersion: tls.VersionTLS12,
CipherSuites: []uint16{
tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
},
}
addLog("\U0001f510 TLS enabled", "SECURITY")
serveErr = srv.ListenAndServeTLS(tlsCert, tlsKey)
} else {
addLog("ℹ️ TLS not configured - running HTTP only", "INFO")
serveErr = srv.ListenAndServe()
}
if serveErr != nil && serveErr != http.ErrServerClosed {
log.Fatalf("Server error: %v", serveErr)
}
}()
quit := make(chan os.Signal, 1)
signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
<-quit
addLog("\U0001f6d1 Shutting down server gracefully...", "SECURITY")
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
if client.IsConnected() {
client.Disconnect()
}
persistStats()
srv.Shutdown(ctx)
addLog("\u2705 Server stopped.", "SECURITY")
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
http.ServeFile(w, r, "index.html")
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
http.ServeFile(w, r, "admin.html")
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "application/json")
if r.Method != http.MethodPost {
w.Header().Set("Allow", "POST")
http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
return
}
ip := r.RemoteAddr
if idx := strings.LastIndex(ip, ":"); idx != -1 {
ip = ip[:idx]
}
if isIPLocked(ip) {
w.WriteHeader(http.StatusForbidden)
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "IP temporarily locked due to too many failed attempts"})
return
}
var req struct {
Username string `json:"username"`
Password string `json:"password"`
}
if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Invalid request"})
return
}
adminUser := os.Getenv("ADMIN_USER")
adminPass := os.Getenv("ADMIN_PASS")
if adminUser == "" {
adminUser = "admin"
}
if adminPass == "" {
adminPass = "admin123"
}
if req.Username != adminUser || req.Password != adminPass {
addLog(fmt.Sprintf("Failed JWT login attempt from: %s", r.RemoteAddr), "SECURITY")
recordFailedLogin(ip)
w.WriteHeader(http.StatusUnauthorized)
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Invalid credentials"})
return
}
expiresAt := time.Now().Add(24 * time.Hour)
claims := jwt.MapClaims{
"sub": req.Username,
"exp": expiresAt.Unix(),
"iat": time.Now().Unix(),
}
token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
tokenStr, err := token.SignedString(jwtSecret)
if err != nil {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Token generation failed"})
return
}
json.NewEncoder(w).Encode(APIResponse{
Success: true,
Data: map[string]string{
"token":      tokenStr,
"expires_at": expiresAt.UTC().Format(time.RFC3339),
},
})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "application/json")
clientsMu.RLock()
devCount := len(clients)
clientsMu.RUnlock()
connected := client != nil && client.IsConnected()
json.NewEncoder(w).Encode(map[string]interface{}{
"status":             "ok",
"uptime_seconds":     int(time.Since(serverStartTime).Seconds()),
"version":            serverVersion,
"whatsapp_connected": connected,
"devices_count":      devCount,
"timestamp":          time.Now().UTC().Format(time.RFC3339),
})
}

func handleSecurePair(w http.ResponseWriter, r *http.Request) {
phone := r.URL.Query().Get("phone")
if phone == "" {
http.Error(w, "Phone number is required", http.StatusBadRequest)
return
}
if !rateLimitPairing(phone) {
addLog(fmt.Sprintf("\U0001f512 Pairing rate limit exceeded for: %s", phone), "SECURITY")
http.Error(w, "Too many pairing attempts. Please wait 60 seconds.", http.StatusTooManyRequests)
return
}
linkedPhonesMu.RLock()
alreadyLinked := linkedPhones[phone]
linkedPhonesMu.RUnlock()
if alreadyLinked {
w.WriteHeader(http.StatusOK)
fmt.Fprint(w, "Already Linked")
return
}
addLog(fmt.Sprintf("\U0001f4f1 Pairing request from IP: %s for phone: %s", r.RemoteAddr, phone), "SECURITY")
deviceID := r.URL.Query().Get("device")
if deviceID == "" {
deviceID = "default"
}
clientsMu.RLock()
targetClient, ok := clients[deviceID]
clientsMu.RUnlock()
if !ok || targetClient == nil {
targetClient = client
}
if targetClient.Store.ID != nil {
w.Write([]byte("Already Linked"))
return
}
if !targetClient.IsConnected() {
targetClient.Connect()
}
clientName := "Chrome (Linux)"
configMu.RLock()
randomizeUA := config.RandomizeUserAgent
configMu.RUnlock()
if randomizeUA {
clientOptions := []string{"Chrome (Linux)", "Chrome (Windows)", "Chrome (macOS)"}
clientName = clientOptions[mathrand.Intn(len(clientOptions))]
}
code, err := targetClient.PairPhone(r.Context(), phone, true, whatsmeow.PairClientChrome, clientName)
if err != nil {
addLog("\U0001f512 Secure pairing error: "+err.Error(), "SECURITY")
http.Error(w, "Error: "+err.Error(), http.StatusInternalServerError)
return
}
addLog(fmt.Sprintf("\U0001f4f1 Secure pairing code generated for: %s", phone), "SECURITY")
w.Write([]byte(code))
}

func handleIsLinked(w http.ResponseWriter, r *http.Request) {
deviceID := r.URL.Query().Get("device")
if deviceID == "" {
deviceID = "default"
}
clientsMu.RLock()
c, ok := clients[deviceID]
clientsMu.RUnlock()
if !ok || c == nil {
c = client
}
if c != nil && c.Store.ID != nil {
w.Write([]byte("true"))
} else {
w.Write([]byte("false"))
}
}

func handleApiInfo(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "application/json")
deviceID := r.URL.Query().Get("device")
if deviceID == "" {
deviceID = "default"
}
clientsMu.RLock()
c, ok := clients[deviceID]
clientsMu.RUnlock()
if !ok || c == nil {
c = client
}
configMu.RLock()
safeMode := config.SafeMode
configMu.RUnlock()
if c != nil && c.Store.ID != nil {
json.NewEncoder(w).Encode(APIResponse{
Success: true,
Data: map[string]interface{}{
"status":          "Connected",
"jid":             c.Store.ID.User,
"connected":       c.IsConnected(),
"security_active": true,
"safe_mode":       safeMode,
"device_id":       deviceID,
},
})
} else {
json.NewEncoder(w).Encode(APIResponse{
Success: true,
Data: map[string]interface{}{
"status":          "Disconnected",
"jid":             "None",
"connected":       false,
"security_active": true,
"device_id":       deviceID,
},
})
}
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "application/json")
logMu.Lock()
logs := make([]string, len(systemLogs))
copy(logs, systemLogs)
logMu.Unlock()
json.NewEncoder(w).Encode(APIResponse{Success: true, Data: logs})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "application/json")
deviceID := r.URL.Query().Get("device")
if deviceID != "" {
clientsMu.RLock()
c, ok := clients[deviceID]
clientsMu.RUnlock()
if !ok || c == nil {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Device not found"})
return
}
if c.Store.ID != nil {
c.Logout(context.Background())
addLog(fmt.Sprintf("🔴 Device %s logged out by admin", deviceID), "SECURITY")
}
json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "Device logged out"})
} else {
clientsMu.RLock()
allClients := make([]*whatsmeow.Client, 0, len(clients))
for _, c := range clients {
if c != nil {
allClients = append(allClients, c)
}
}
clientsMu.RUnlock()
count := 0
for _, c := range allClients {
if c.Store.ID != nil {
c.Logout(context.Background())
count++
}
}
addLog(fmt.Sprintf("🔴 %d device(s) logged out by admin", count), "SECURITY")
json.NewEncoder(w).Encode(APIResponse{Success: true, Message: fmt.Sprintf("Logged out %d device(s)", count)})
}
}

func handleSecureConfig(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "application/json")
if r.Method == http.MethodGet {
configMu.RLock()
currentConfig := config
configMu.RUnlock()
json.NewEncoder(w).Encode(APIResponse{
Success: true,
Data:    currentConfig,
Warning: "Security features active - some limits may apply",
})
} else if r.Method == http.MethodPost {
var newConfig AutoConfig
if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Invalid configuration format"})
return
}
if newConfig.DailySendLimit > 500 {
newConfig.DailySendLimit = 500
addLog("\U0001f512 Daily limit capped at 500 for security", "SECURITY")
}
if newConfig.MinSendDelay < 3 {
newConfig.MinSendDelay = 3
addLog("\U0001f512 Min send delay enforced to 3 seconds", "SECURITY")
}
configMu.Lock()
config = newConfig
configMu.Unlock()
saveConfig()
addLog("\u2699\ufe0f Secure configuration updated by admin", "SECURITY")
json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "Configuration saved with security enhancements"})
} else {
w.Header().Set("Allow", "GET, POST")
http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}
}

func handleSecureSend(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "application/json")
var targetPhone, msgText, deviceID string
if r.Method == http.MethodPost {
var req struct {
Phone    string `json:"phone"`
Text     string `json:"text"`
DeviceID string `json:"device"`
}
if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Invalid JSON body"})
return
}
targetPhone = req.Phone
msgText = req.Text
deviceID = req.DeviceID
} else {
// fallback to GET query params (deprecated but kept for backward compat)
targetPhone = r.URL.Query().Get("phone")
msgText = r.URL.Query().Get("text")
deviceID = r.URL.Query().Get("device")
}
if targetPhone == "" || msgText == "" {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Phone and text parameters required"})
return
}
targetPhone = strings.ReplaceAll(targetPhone, "+", "")
targetPhone = strings.ReplaceAll(targetPhone, " ", "")
targetPhone = strings.ReplaceAll(targetPhone, "-", "")
if len(targetPhone) < 7 {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Invalid phone number"})
return
}
if len(targetPhone) == 10 && !strings.HasPrefix(targetPhone, "91") {
targetPhone = "91" + targetPhone
}
if safe, reason := isSendingSafe(targetPhone); !safe {
json.NewEncoder(w).Encode(APIResponse{
Success: false,
Message: "Send blocked by security: " + reason,
Warning: "Anti-ban protection active",
})
return
}
// deviceID already set above
if deviceID == "" {
deviceID = "default"
}
clientsMu.RLock()
targetClient, ok := clients[deviceID]
clientsMu.RUnlock()
if !ok || targetClient == nil {
targetClient = client
}
if targetClient == nil || !targetClient.IsConnected() {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Device not connected"})
return
}
targetJID := types.NewJID(targetPhone, "s.whatsapp.net")
msg := &waProto.Message{Conversation: proto.String(msgText)}
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
_, sendErr := targetClient.SendMessage(ctx, targetJID, msg)
success := sendErr == nil
if success {
updateMessageStats(true)
addToHistory("sent", targetPhone, msgText, "success")
go writeToSupabase("message_history", map[string]interface{}{
"direction": "sent",
"phone":     targetPhone,
"message":   msgText,
"status":    "sent",
})
go persistStats()
} else {
updateMessageStats(false)
addToHistory("sent", targetPhone, msgText, "failed")
go writeToSupabase("message_history", map[string]interface{}{
"direction": "sent",
"phone":     targetPhone,
"message":   msgText,
"status":    "failed",
})
}
json.NewEncoder(w).Encode(APIResponse{
Success: success,
Message: fmt.Sprintf("Message %s", map[bool]string{true: "sent securely", false: "failed to send"}[success]),
})
}

func handleSendMedia(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "application/json")
if r.Method != http.MethodPost {
w.Header().Set("Allow", "POST")
http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
return
}
var req MediaSendRequest
if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Invalid request"})
return
}
phone := strings.ReplaceAll(req.Phone, "+", "")
phone = strings.ReplaceAll(phone, " ", "")
phone = strings.ReplaceAll(phone, "-", "")
if len(phone) < 7 {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Invalid phone number"})
return
}
if len(phone) == 10 && !strings.HasPrefix(phone, "91") {
phone = "91" + phone
}
if req.URL == "" {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "URL is required"})
return
}
dlClient := &http.Client{Timeout: 30 * time.Second}
resp, err := dlClient.Get(req.URL)
if err != nil || resp.StatusCode != http.StatusOK {
if err == nil {
resp.Body.Close()
}
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to download media"})
return
}
defer resp.Body.Close()
const maxMediaSize = 50 * 1024 * 1024 // 50 MB
data, err := io.ReadAll(io.LimitReader(resp.Body, maxMediaSize))
if err != nil {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to read media"})
return
}
deviceID := r.URL.Query().Get("device")
if deviceID == "" {
deviceID = "default"
}
clientsMu.RLock()
targetClient, ok := clients[deviceID]
clientsMu.RUnlock()
if !ok || targetClient == nil {
targetClient = client
}
ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
defer cancel()
targetJID := types.NewJID(phone, "s.whatsapp.net")
mediaType := req.Type
if mediaType == "" {
mediaType = "image"
}
var msg *waProto.Message
if mediaType == "document" {
uploaded, err := targetClient.Upload(ctx, data, whatsmeow.MediaDocument)
if err != nil {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Upload failed: " + err.Error()})
return
}
mimeType := resp.Header.Get("Content-Type")
if mimeType == "" {
mimeType = "application/octet-stream"
}
msg = &waProto.Message{
DocumentMessage: &waProto.DocumentMessage{
URL:           proto.String(uploaded.URL),
MediaKey:      uploaded.MediaKey,
FileEncSHA256: uploaded.FileEncSHA256,
FileSHA256:    uploaded.FileSHA256,
FileLength:    proto.Uint64(uploaded.FileLength),
Caption:       proto.String(req.Caption),
Mimetype:      proto.String(mimeType),
},
}
} else {
uploaded, err := targetClient.Upload(ctx, data, whatsmeow.MediaImage)
if err != nil {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Upload failed: " + err.Error()})
return
}
mimeType := resp.Header.Get("Content-Type")
if mimeType == "" {
mimeType = "image/jpeg"
}
msg = &waProto.Message{
ImageMessage: &waProto.ImageMessage{
URL:           proto.String(uploaded.URL),
MediaKey:      uploaded.MediaKey,
FileEncSHA256: uploaded.FileEncSHA256,
FileSHA256:    uploaded.FileSHA256,
FileLength:    proto.Uint64(uploaded.FileLength),
Caption:       proto.String(req.Caption),
Mimetype:      proto.String(mimeType),
},
}
}
if _, err := targetClient.SendMessage(ctx, targetJID, msg); err != nil {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to send: " + err.Error()})
return
}
json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "Media sent successfully"})
}

func handleWebhookTest(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "application/json")
if r.Method != http.MethodPost {
w.Header().Set("Allow", "POST")
http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
return
}
payload := map[string]interface{}{
"event":     "test",
"timestamp": time.Now().UTC().Format(time.RFC3339),
"message":   "test",
}
go fireWebhook(payload)
json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "Test webhook fired"})
}

func handleDevices(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "application/json")
switch r.Method {
case http.MethodGet:
clientsMu.RLock()
devices := make([]DeviceInfo, 0, len(clients))
for id, c := range clients {
info := DeviceInfo{
ID:        id,
Connected: c != nil && c.IsConnected(),
Name:      "WhatsApp Device",
}
if c != nil && c.Store != nil && c.Store.ID != nil {
info.JID   = c.Store.ID.String()
info.Phone = c.Store.ID.User
}
devices = append(devices, info)
}
clientsMu.RUnlock()
json.NewEncoder(w).Encode(APIResponse{Success: true, Data: devices})
case http.MethodPost:
var req struct {
DeviceID string `json:"device_id"`
}
if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DeviceID == "" {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "device_id is required"})
return
}
clientsMu.RLock()
_, exists := clients[req.DeviceID]
clientsMu.RUnlock()
if exists {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Device already exists"})
return
}
dbFile := fmt.Sprintf("file:session_%s.db?_foreign_keys=on", req.DeviceID)
dbLog := waLog.Stdout("Database", "ERROR", true)
cont, err := sqlstore.New(context.Background(), "sqlite3", dbFile, dbLog)
if err != nil {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to create device DB: " + err.Error()})
return
}
ds, err := cont.GetFirstDevice(context.Background())
if err != nil {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to get device store: " + err.Error()})
return
}
clientLog := waLog.Stdout("Client", "ERROR", true)
newClient := whatsmeow.NewClient(ds, clientLog)
newClient.EnableAutoReconnect = true
newClient.AutoTrustIdentity = false
newClient.AddEventHandler(eventHandler)
clientsMu.Lock()
clients[req.DeviceID] = newClient
clientsMu.Unlock()
json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "Device added", Data: DeviceInfo{ID: req.DeviceID, Connected: false}})
case http.MethodDelete:
deviceID := r.URL.Query().Get("id")
if deviceID == "" || deviceID == "default" {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Cannot delete default device"})
return
}
clientsMu.Lock()
c, exists := clients[deviceID]
if exists {
if c != nil && c.IsConnected() {
c.Disconnect()
}
delete(clients, deviceID)
}
clientsMu.Unlock()
if !exists {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Device not found"})
return
}
json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "Device removed"})
default:
w.Header().Set("Allow", "GET, POST, DELETE")
http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}
}

func handleHistory(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "application/json")
page := 1
limit := 50
if v := r.URL.Query().Get("page"); v != "" {
if n, err := strconv.Atoi(v); err == nil && n > 0 {
page = n
}
}
if v := r.URL.Query().Get("limit"); v != "" {
if n, err := strconv.Atoi(v); err == nil && n > 0 {
if n > 200 {
n = 200
}
limit = n
}
}
historyMu.Lock()
total := len(messageHistory)
start := (page - 1) * limit
end := start + limit
if start > total {
start = total
}
if end > total {
end = total
}
slice := make([]MessageLogEntry, end-start)
copy(slice, messageHistory[start:end])
historyMu.Unlock()
json.NewEncoder(w).Encode(APIResponse{
Success: true,
Data: map[string]interface{}{
"entries": slice,
"total":   total,
"page":    page,
"limit":   limit,
},
})
}

func handleSecureStats(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "application/json")
configMu.RLock()
safeMode := config.SafeMode
dailySendLimit := config.DailySendLimit
hourlySendLimit := config.HourlySendLimit
configMu.RUnlock()
statsMu.Lock()
securityStatus := "SECURE"
if messageStats.BanWarnings > 10 {
securityStatus = "CRITICAL"
} else if messageStats.BanWarnings > 5 {
securityStatus = "WARNING"
}
now := time.Now()
enhancedStats := map[string]interface{}{
"message_stats":    messageStats,
"security_status":  securityStatus,
"ban_warnings":     messageStats.BanWarnings,
"safe_mode":        safeMode,
"daily_remaining":  dailySendLimit - messageStats.DailyCounts[now.Format("2006-01-02")],
"hourly_remaining": hourlySendLimit - messageStats.HourlyCounts[now.Format("2006-01-02-15")],
}
json.NewEncoder(w).Encode(APIResponse{Success: true, Data: enhancedStats})
statsMu.Unlock()
}

func handleStatsWithDelete(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "application/json")
if r.Method == http.MethodDelete {
statsMu.Lock()
messageStats = MessageStats{
DailyCounts:  make(map[string]int),
HourlyCounts: make(map[string]int),
}
statsMu.Unlock()
if statsDB != nil {
statsDB.Exec("DELETE FROM daily_stats")
}
json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "Stats reset"})
return
}
handleSecureStats(w, r)
}

func handleSecurityStatus(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "application/json")
configMu.RLock()
safeMode := config.SafeMode
randomizeUA := config.RandomizeUserAgent
dailyLimit := config.DailySendLimit
hourlyLimit := config.HourlySendLimit
minSendDelay := config.MinSendDelay
configMu.RUnlock()
statsMu.Lock()
banWarnings := messageStats.BanWarnings
statsMu.Unlock()
securityInfo := map[string]interface{}{
"safe_mode_active":    safeMode,
"ban_warnings":        banWarnings,
"rate_limiting":       true,
"user_agent_rotation": randomizeUA,
"daily_limit":         dailyLimit,
"hourly_limit":        hourlyLimit,
"min_send_delay":      minSendDelay,
"last_security_check": time.Now(),
"security_level":      "HIGH",
}
json.NewEncoder(w).Encode(APIResponse{
Success: true,
Data:    securityInfo,
Message: "Security systems operational",
})
}

func handleSchedule(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "application/json")
if r.Method == http.MethodGet {
scheduleMu.Lock()
msgs := make([]ScheduledMessage, len(scheduledMessages))
copy(msgs, scheduledMessages)
scheduleMu.Unlock()
json.NewEncoder(w).Encode(APIResponse{Success: true, Data: msgs})
} else if r.Method == http.MethodPost {
var req struct {
Phone       string `json:"phone"`
Message     string `json:"message"`
ScheduledAt string `json:"scheduled_at"`
}
if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Invalid request format"})
return
}
if req.Phone == "" || req.Message == "" || req.ScheduledAt == "" {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "phone, message, and scheduled_at are required"})
return
}
scheduledAt, err := time.Parse(time.RFC3339, req.ScheduledAt)
if err != nil {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "scheduled_at must be in RFC3339 format"})
return
}
idBytes := make([]byte, 8)
if _, err := rand.Read(idBytes); err != nil {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to generate message ID"})
return
}
msg := ScheduledMessage{
ID:          fmt.Sprintf("%x", idBytes),
Phone:       req.Phone,
Message:     req.Message,
ScheduledAt: scheduledAt,
Status:      "pending",
}
scheduleMu.Lock()
scheduledMessages = append(scheduledMessages, msg)
scheduleMu.Unlock()
go writeToSupabase("scheduled_messages", map[string]interface{}{
"id":           msg.ID,
"phone":        msg.Phone,
"message":      msg.Message,
"scheduled_at": msg.ScheduledAt.UTC().Format(time.RFC3339),
"status":       "pending",
})
addLog(fmt.Sprintf("\u23f0 Scheduled message added for %s at %s", req.Phone, scheduledAt.Format(time.RFC3339)), "INFO")
json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "Scheduled message added", Data: msg})
} else if r.Method == http.MethodDelete {
id := r.URL.Query().Get("id")
if id == "" {
w.WriteHeader(http.StatusBadRequest)
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Missing id"})
return
}
scheduleMu.Lock()
found := false
for i, m := range scheduledMessages {
if m.ID == id {
scheduledMessages = append(scheduledMessages[:i], scheduledMessages[i+1:]...)
found = true
break
}
}
scheduleMu.Unlock()
if found {
json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "Scheduled message deleted"})
} else {
w.WriteHeader(http.StatusNotFound)
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Message not found"})
}
} else {
w.Header().Set("Allow", "GET, POST, DELETE")
http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}
}

func secureMessageScheduler() {
ticker := time.NewTicker(60 * time.Second)
defer ticker.Stop()
for range ticker.C {
now := time.Now()

// Collect pending messages under lock, mark as processing to avoid double-send
scheduleMu.Lock()
var toSend []ScheduledMessage
for i := range scheduledMessages {
if scheduledMessages[i].Status == "pending" && now.After(scheduledMessages[i].ScheduledAt) {
toSend = append(toSend, scheduledMessages[i])
scheduledMessages[i].Status = "processing"
}
}
// Cleanup expired messages (reverse loop to avoid index shift)
for i := len(scheduledMessages) - 1; i >= 0; i-- {
if now.Sub(scheduledMessages[i].ScheduledAt) > 48*time.Hour {
scheduledMessages = append(scheduledMessages[:i], scheduledMessages[i+1:]...)
}
}
scheduleMu.Unlock()

// Send outside the lock to prevent deadlock; use ID-based updates
for _, msg := range toSend {
if safe, reason := isSendingSafe(msg.Phone); !safe {
addLog(fmt.Sprintf("🔒 Scheduled message blocked: %s", reason), "SECURITY")
scheduleMu.Lock()
for i := range scheduledMessages {
if scheduledMessages[i].ID == msg.ID {
scheduledMessages[i].Status = "blocked"
break
}
}
scheduleMu.Unlock()
continue
}
if sendSecureMessage(msg.Phone, msg.Message) {
scheduleMu.Lock()
for i := range scheduledMessages {
if scheduledMessages[i].ID == msg.ID {
scheduledMessages[i].Status = "sent"
break
}
}
scheduleMu.Unlock()
addLog(fmt.Sprintf("⏰ Scheduled message securely sent to %s", msg.Phone))
go writeToSupabaseUpsert("scheduled_messages", map[string]interface{}{
"id":     msg.ID,
"status": "sent",
})
} else {
var attempts int
scheduleMu.Lock()
for i := range scheduledMessages {
if scheduledMessages[i].ID == msg.ID {
scheduledMessages[i].Status = "failed"
scheduledMessages[i].Attempts++
attempts = scheduledMessages[i].Attempts
break
}
}
scheduleMu.Unlock()
addLog(fmt.Sprintf("❌ Scheduled message failed to %s (attempt %d)", msg.Phone, attempts), "ERROR")
go writeToSupabaseUpsert("scheduled_messages", map[string]interface{}{
"id":     msg.ID,
"status": "failed",
})
}
}
}
}

// handleAPIKeys handles GET/POST/DELETE /api/keys
func handleAPIKeys(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "application/json")
switch r.Method {
case http.MethodGet:
apiKeysMu.RLock()
keys := make([]APIKey, len(apiKeys))
copy(keys, apiKeys)
apiKeysMu.RUnlock()
// Redact key values, keep last 4 chars
for i := range keys {
if len(keys[i].Key) > 4 {
keys[i].Key = strings.Repeat("*", len(keys[i].Key)-4) + keys[i].Key[len(keys[i].Key)-4:]
} else {
keys[i].Key = strings.Repeat("*", len(keys[i].Key))
}
}
json.NewEncoder(w).Encode(APIResponse{Success: true, Data: keys})
case http.MethodPost:
var req struct {
Name string `json:"name"`
Role string `json:"role"`
}
if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "name is required"})
return
}
if req.Role == "" {
req.Role = "user"
}
keyBytes := make([]byte, 32)
rand.Read(keyBytes)
idBytes := make([]byte, 8)
rand.Read(idBytes)
newKey := APIKey{
ID:        fmt.Sprintf("%x", idBytes),
Key:       "wak_" + hex.EncodeToString(keyBytes),
Name:      req.Name,
Role:      req.Role,
CreatedAt: time.Now(),
Active:    true,
}
apiKeysMu.Lock()
apiKeys = append(apiKeys, newKey)
apiKeysMu.Unlock()
saveAPIKeys()
addLog(fmt.Sprintf("API key created: %s (%s)", req.Name, req.Role), "SECURITY")
json.NewEncoder(w).Encode(APIResponse{Success: true, Data: newKey, Message: "API key created"})
case http.MethodDelete:
// Support deletion by id or by full key
id := r.URL.Query().Get("id")
key := r.URL.Query().Get("key")
if id == "" && key == "" {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "id or key query parameter required"})
return
}
apiKeysMu.Lock()
found := false
for i, k := range apiKeys {
if (id != "" && k.ID == id) || (key != "" && k.Key == key) {
apiKeys = append(apiKeys[:i], apiKeys[i+1:]...)
found = true
break
}
}
apiKeysMu.Unlock()
if !found {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "API key not found"})
return
}
saveAPIKeys()
addLog("API key deleted", "SECURITY")
json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "API key deleted"})
default:
w.Header().Set("Allow", "GET, POST, DELETE")
http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}
}

// handleLockouts handles GET/DELETE /api/security/lockouts
func handleLockouts(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "application/json")
switch r.Method {
case http.MethodGet:
loginAttemptsMu.Lock()
result := make(map[string]interface{})
for ip, a := range loginAttempts {
if a.Count > 0 {
result[ip] = map[string]interface{}{
"count":      a.Count,
"locked":     time.Now().Before(a.LockUntil),
"lock_until": a.LockUntil,
"locked_at":  a.LockedAt,
}
}
}
loginAttemptsMu.Unlock()
json.NewEncoder(w).Encode(APIResponse{Success: true, Data: result})
case http.MethodDelete:
ip := r.URL.Query().Get("ip")
loginAttemptsMu.Lock()
if ip != "" {
delete(loginAttempts, ip)
} else {
loginAttempts = make(map[string]*LoginAttempt)
}
loginAttemptsMu.Unlock()
addLog("Lockout cleared", "SECURITY")
json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "Lockout(s) cleared"})
default:
w.Header().Set("Allow", "GET, DELETE")
http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}
}

// handleBulkSend handles POST /api/bulk-send (multipart CSV file)
func handleBulkSend(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "application/json")
if r.Method != http.MethodPost {
w.Header().Set("Allow", "POST")
http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
return
}
if err := r.ParseMultipartForm(10 << 20); err != nil {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to parse multipart form"})
return
}
file, _, err := r.FormFile("file")
if err != nil {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "file field is required"})
return
}
defer file.Close()

reader := csv.NewReader(file)
records, err := reader.ReadAll()
if err != nil {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Failed to parse CSV: " + err.Error()})
return
}

type csvRow struct {
phone   string
message string
}
var rows []csvRow
for i, rec := range records {
if i == 0 {
// skip header if columns are phone,message
if len(rec) >= 2 && strings.ToLower(strings.TrimSpace(rec[0])) == "phone" {
continue
}
}
if len(rec) < 2 {
continue
}
rows = append(rows, csvRow{phone: strings.TrimSpace(rec[0]), message: strings.TrimSpace(rec[1])})
}

if len(rows) == 0 {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "No valid rows found in CSV"})
return
}

deviceID := r.FormValue("device")
if deviceID == "" {
deviceID = "default"
}
clientsMu.RLock()
targetClient, ok := clients[deviceID]
clientsMu.RUnlock()
if !ok || targetClient == nil {
targetClient = client
}
if targetClient == nil || !targetClient.IsConnected() {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Device not connected. Please link a WhatsApp device first."})
return
}

idBytes := make([]byte, 8)
rand.Read(idBytes)
job := &BulkSendJob{
ID:         fmt.Sprintf("%x", idBytes),
Status:     "running",
Total:      len(rows),
CreatedAt:  time.Now(),
UpdatedAt:  time.Now(),
CancelChan: make(chan struct{}),
PauseChan:  make(chan bool, 1),
}
bulkJobsMu.Lock()
bulkJobs = append(bulkJobs, job)
bulkJobsMu.Unlock()
go writeToSupabase("bulk_jobs", map[string]interface{}{
"id":         job.ID,
"status":     job.Status,
"total":      job.Total,
"progress":   job.Progress,
"sent":       job.Sent,
"failed":     job.Failed,
"created_at": job.CreatedAt.UTC().Format(time.RFC3339),
})

go func() {
for _, row := range rows {
// Check for cancellation
select {
case <-job.CancelChan:
bulkJobsMu.Lock()
job.Status = "cancelled"
job.UpdatedAt = time.Now()
bulkJobsMu.Unlock()
go writeToSupabaseUpsert("bulk_jobs", map[string]interface{}{
"id":     job.ID,
"status": "cancelled",
})
return
default:
}

// Non-blocking check for pause signal
select {
case paused := <-job.PauseChan:
if paused {
// Block until resumed or cancelled
pauseLoop:
for {
select {
case <-job.CancelChan:
bulkJobsMu.Lock()
job.Status = "cancelled"
job.UpdatedAt = time.Now()
bulkJobsMu.Unlock()
go writeToSupabaseUpsert("bulk_jobs", map[string]interface{}{
"id":     job.ID,
"status": "cancelled",
})
return
case p := <-job.PauseChan:
if !p {
break pauseLoop
}
}
}
}
default:
}

phone := strings.ReplaceAll(row.phone, "+", "")
phone = strings.ReplaceAll(phone, "-", "")
phone = strings.ReplaceAll(phone, " ", "")
if len(phone) < 7 {
bulkJobsMu.Lock()
job.Failed++
job.Progress = job.Sent + job.Failed
job.UpdatedAt = time.Now()
bulkJobsMu.Unlock()
continue
}
ok := sendSecureMessageWithClient(phone, row.message, targetClient)
bulkJobsMu.Lock()
if ok {
job.Sent++
} else {
job.Failed++
}
job.Progress = job.Sent + job.Failed
job.UpdatedAt = time.Now()
jobID, jobSent, jobFailed, jobProgress := job.ID, job.Sent, job.Failed, job.Progress
bulkJobsMu.Unlock()
go writeToSupabaseUpsert("bulk_jobs", map[string]interface{}{
"id":       jobID,
"progress": jobProgress,
"sent":     jobSent,
"failed":   jobFailed,
"status":   "running",
})
time.Sleep(calculateSmartDelay())
}
bulkJobsMu.Lock()
job.Status = "completed"
job.UpdatedAt = time.Now()
completedID, completedSent, completedFailed, completedProgress := job.ID, job.Sent, job.Failed, job.Progress
bulkJobsMu.Unlock()
go writeToSupabaseUpsert("bulk_jobs", map[string]interface{}{
"id":       completedID,
"status":   "completed",
"sent":     completedSent,
"failed":   completedFailed,
"progress": completedProgress,
})
addLog(fmt.Sprintf("Bulk send job %s completed: %d sent, %d failed", job.ID, job.Sent, job.Failed), "INFO")
}()

json.NewEncoder(w).Encode(APIResponse{Success: true, Data: job, Message: "Bulk send job started"})
}

// handleBulkSendJobs handles GET/DELETE /api/bulk-send/jobs
func handleBulkSendJobs(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "application/json")
switch r.Method {
case http.MethodGet:
bulkJobsMu.Lock()
jobs := make([]*BulkSendJob, len(bulkJobs))
copy(jobs, bulkJobs)
bulkJobsMu.Unlock()
json.NewEncoder(w).Encode(APIResponse{Success: true, Data: jobs})
case http.MethodDelete:
id := r.URL.Query().Get("id")
bulkJobsMu.Lock()
if id != "" {
for i, j := range bulkJobs {
if j.ID == id {
bulkJobs = append(bulkJobs[:i], bulkJobs[i+1:]...)
break
}
}
} else {
bulkJobs = nil
}
bulkJobsMu.Unlock()
json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "Job(s) deleted"})
default:
w.Header().Set("Allow", "GET, DELETE")
http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}
}

func handleBulkJobCancel(w http.ResponseWriter, r *http.Request) {
if r.Method != http.MethodPost {
http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
return
}
w.Header().Set("Content-Type", "application/json")
id := r.URL.Query().Get("id")
bulkJobsMu.Lock()
var found *BulkSendJob
for _, j := range bulkJobs {
if j.ID == id {
found = j
break
}
}
bulkJobsMu.Unlock()
if found == nil {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Job not found"})
return
}
if found.Status != "running" && found.Status != "paused" {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Job is not running"})
return
}
found.cancelOnce.Do(func() { close(found.CancelChan) })
json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "Job cancelled"})
}

func handleBulkJobPause(w http.ResponseWriter, r *http.Request) {
if r.Method != http.MethodPost {
http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
return
}
w.Header().Set("Content-Type", "application/json")
id := r.URL.Query().Get("id")
bulkJobsMu.Lock()
var found *BulkSendJob
for _, j := range bulkJobs {
if j.ID == id {
found = j
break
}
}
if found != nil {
found.Paused = true
found.Status = "paused"
found.UpdatedAt = time.Now()
}
bulkJobsMu.Unlock()
if found == nil {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Job not found"})
return
}
found.PauseChan <- true
go writeToSupabaseUpsert("bulk_jobs", map[string]interface{}{"id": found.ID, "status": "paused"})
json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "Job paused"})
}

func handleBulkJobResume(w http.ResponseWriter, r *http.Request) {
if r.Method != http.MethodPost {
http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
return
}
w.Header().Set("Content-Type", "application/json")
id := r.URL.Query().Get("id")
bulkJobsMu.Lock()
var found *BulkSendJob
for _, j := range bulkJobs {
if j.ID == id {
found = j
break
}
}
if found != nil {
found.Paused = false
found.Status = "running"
found.UpdatedAt = time.Now()
}
bulkJobsMu.Unlock()
if found == nil {
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Job not found"})
return
}
found.PauseChan <- false
go writeToSupabaseUpsert("bulk_jobs", map[string]interface{}{"id": found.ID, "status": "running"})
json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "Job resumed"})
}

// handleDelivery handles GET /api/delivery?phone=...
func handleDelivery(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "application/json")
if r.Method != http.MethodGet {
w.Header().Set("Allow", "GET")
http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
return
}
phone := r.URL.Query().Get("phone")
historyMu.Lock()
var result []MessageLogEntry
for _, e := range messageHistory {
if e.Direction == "sent" && (phone == "" || e.Phone == phone) {
result = append(result, e)
}
}
historyMu.Unlock()
json.NewEncoder(w).Encode(APIResponse{Success: true, Data: result})
}

func handleRestart(w http.ResponseWriter, r *http.Request) {
if r.Method != http.MethodPost {
http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
return
}
w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "Server restarting..."})
addLog("🔄 Server restart requested via admin panel", "SECURITY")
go func() {
time.Sleep(500 * time.Millisecond)
// Cancel all active bulk jobs
bulkJobsMu.Lock()
for _, j := range bulkJobs {
if j.Status == "running" {
select {
case j.CancelChan <- struct{}{}:
default:
}
}
}
bulkJobsMu.Unlock()
// Persist stats before exit
persistStats()
// Gracefully disconnect all WhatsApp clients
clientsMu.RLock()
allClients := make([]*whatsmeow.Client, 0, len(clients))
for _, c := range clients {
if c != nil {
allClients = append(allClients, c)
}
}
clientsMu.RUnlock()
for _, c := range allClients {
if c.IsConnected() {
c.Disconnect()
}
}
time.Sleep(300 * time.Millisecond)
os.Exit(0)
}()
}

func handleDisconnectAll(w http.ResponseWriter, r *http.Request) {
if r.Method != http.MethodPost {
http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
return
}
clientsMu.Lock()
count := 0
for _, c := range clients {
if c != nil && c.IsConnected() {
c.Disconnect()
count++
}
}
clientsMu.Unlock()
addLog(fmt.Sprintf("🔌 Disconnected %d device(s) via admin panel", count), "SECURITY")
w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(APIResponse{Success: true, Message: fmt.Sprintf("Disconnected %d device(s)", count)})
}

func handleAutomation(w http.ResponseWriter, r *http.Request) {
w.Header().Set("Content-Type", "application/json")
switch r.Method {
case http.MethodGet:
configMu.RLock()
data := map[string]interface{}{
"enabled":      config.Enabled,
"numbers":      config.Numbers,
"message":      config.Message,
"reply_enable": config.ReplyEnable,
"reply_text":   config.ReplyText,
"send_delay":   config.SendDelay,
}
configMu.RUnlock()
json.NewEncoder(w).Encode(APIResponse{Success: true, Data: data})
case http.MethodPost:
var body map[string]interface{}
if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
w.WriteHeader(http.StatusBadRequest)
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Invalid JSON"})
return
}
configMu.Lock()
if v, ok := body["enabled"].(bool); ok {
config.Enabled = v
}
if v, ok := body["numbers"].(string); ok {
config.Numbers = v
}
if v, ok := body["message"].(string); ok {
config.Message = v
}
if v, ok := body["reply_enable"].(bool); ok {
config.ReplyEnable = v
}
if v, ok := body["reply_text"].(string); ok {
config.ReplyText = v
}
if v, ok := body["send_delay"].(float64); ok {
config.SendDelay = int(v)
}
configMu.Unlock()
go saveConfig()
addLog("⚙️ Automation settings updated via admin panel", "INFO")
json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "Automation settings saved"})
default:
http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}
}

func handleRestore(w http.ResponseWriter, r *http.Request) {
if r.Method != http.MethodPost {
http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
return
}
w.Header().Set("Content-Type", "application/json")

if err := r.ParseMultipartForm(10 << 20); err != nil {
r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
var backup map[string]interface{}
if err2 := json.NewDecoder(r.Body).Decode(&backup); err2 != nil {
w.WriteHeader(http.StatusBadRequest)
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Invalid backup file"})
return
}
restoreFromBackupMap(backup)
addLog("📦 Settings restored from backup (JSON body) via admin panel", "SECURITY")
json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "Settings restored from backup"})
return
}

file, _, err := r.FormFile("backup")
if err != nil {
w.WriteHeader(http.StatusBadRequest)
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "No backup file provided"})
return
}
defer file.Close()

var backup map[string]interface{}
if err := json.NewDecoder(file).Decode(&backup); err != nil {
w.WriteHeader(http.StatusBadRequest)
json.NewEncoder(w).Encode(APIResponse{Success: false, Message: "Invalid JSON in backup file"})
return
}

restoreFromBackupMap(backup)
addLog("📦 Settings restored from backup file via admin panel", "SECURITY")
json.NewEncoder(w).Encode(APIResponse{Success: true, Message: "Settings restored successfully"})
}

func restoreFromBackupMap(backup map[string]interface{}) {
if configData, ok := backup["config"]; ok {
if configBytes, err := json.Marshal(configData); err == nil {
var restoredConfig AutoConfig
if err := json.Unmarshal(configBytes, &restoredConfig); err == nil {
configMu.Lock()
config = restoredConfig
configMu.Unlock()
go saveConfig()
}
}
}
if keysData, ok := backup["api_keys"]; ok {
if keysBytes, err := json.Marshal(keysData); err == nil {
var restoredKeys []APIKey
if err := json.Unmarshal(keysBytes, &restoredKeys); err == nil {
apiKeysMu.Lock()
apiKeys = restoredKeys
apiKeysMu.Unlock()
go saveAPIKeys()
}
}
}
}
