#ifndef WPS_BEACON_IE_H
#define WPS_BEACON_IE_H

#include <Arduino.h>

#define PIXIE_RISK_UNKNOWN  0
#define PIXIE_RISK_LOW      1
#define PIXIE_RISK_MEDIUM   2
#define PIXIE_RISK_HIGH     3

struct wps_device_info_t {
    bool    valid;
    char    manufacturer[64];
    char    model_name[64];
    char    model_number[32];
    char    serial_number[32];
    char    device_name[64];
    bool    ap_setup_locked;
    uint8_t pixie_risk;
    char    pixie_note[80];
};

extern wps_device_info_t wps_device_info;

bool wps_capture_device_info(const uint8_t *bssid, int channel, uint32_t timeout_ms = 3000);
int  wps_serial_to_pins(const char *serial, char pins[][9], int max_pins);
void wps_assess_pixie_risk(wps_device_info_t &info);
uint8_t wps_pin_checksum(uint32_t pin7);

#endif
