#ifndef WEB_INTERFACE_H
#define WEB_INTERFACE_H

void start_web_interface();
void web_interface_handle_client();

// Evil Twin şifre testi durumu — main.cpp'den erişilir
extern bool   et_test_pending;   // submit alındı, test bekleniyor
extern bool   et_result_ready;   // test tamamlandı
extern bool   et_result_correct; // test sonucu
extern String et_tested_ssid;
extern String et_tested_password;

#endif
