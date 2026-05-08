#ifndef DEFINITIONS_H
#define DEFINITIONS_H

#define AP_SSID "ESP32-Deauther"
#define AP_PASS "esp32wroom32"
#define SERIAL_DEBUG
#define CHANNEL_MAX 13
#define NUM_FRAMES_PER_DEAUTH 20
#define DEAUTH_BLINK_TIMES 2
#define DEAUTH_BLINK_DURATION 20
#define DEAUTH_TYPE_SINGLE 0
#define DEAUTH_TYPE_ALL 1
#define DEAUTH_TYPE_EVIL_TWIN 2

// Hedef yeniden tarama aralığı (ms)
#define RETRACK_INTERVAL_MS 25000
// CSA beacon gönderim aralığı (ms) — iOS PMF bypass
#define CSA_INTERVAL_MS 2000
// Evil Twin şifre testi sırasında sunucu cevap döngüsü (ms)
#define ET_TEST_TIMEOUT_MS 9000

// ESP32-C3 Super Mini — standart LED yok
#if defined(CONFIG_IDF_TARGET_ESP32C3)
  // LED tanımsız
#else
  #define LED 2
#endif

#ifdef SERIAL_DEBUG
#define DEBUG_PRINT(...)   Serial.print(__VA_ARGS__)
#define DEBUG_PRINTLN(...) Serial.println(__VA_ARGS__)
#define DEBUG_PRINTF(...)  Serial.printf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...)
#define DEBUG_PRINTLN(...)
#define DEBUG_PRINTF(...)
#endif

#ifdef LED
#define BLINK_LED(n, d) blink_led(n, d)
#else
#define BLINK_LED(n, d)
#endif

void blink_led(int num_times, int blink_duration);

#endif
