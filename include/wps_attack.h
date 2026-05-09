#ifndef WPS_ATTACK_H
#define WPS_ATTACK_H

#include <Arduino.h>

#define WPS_MAX_TARGETS    20
#define WPS_PIN_TIMEOUT_MS 18000   // Her PIN denemesi için maks süre (ms)

struct wps_target_t {
  char    ssid[33];
  uint8_t bssid[6];
  int     channel;
  int32_t rssi;
};

enum wps_state_t {
  WPS_IDLE,
  WPS_SCANNING,
  WPS_ATTACKING,
  WPS_SUCCESS,
  WPS_EXHAUSTED,
  WPS_STOPPED,
};

extern wps_target_t wps_targets[];
extern int          wps_target_count;
extern wps_state_t  wps_attack_state;
extern int          wps_attempt;       // Kaçıncı PIN deneniyor
extern int          wps_total;         // Toplam denenecek PIN sayısı
extern char         wps_current_pin[9];
extern char         wps_found_pin[9];
extern char         wps_found_ssid[33];
extern char         wps_found_pass[65];

void wps_scan();
void wps_start_attack(int target_index);
void wps_stop();
void wps_loop();

#endif
