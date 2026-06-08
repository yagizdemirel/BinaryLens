AD SOYAD :  YAĞIZ VEYSEL DEMİREL
EĞİTİMCİ: Keyvan Arasteh Abbasabad
OKUL NUMARASI 2420191029


# 🔥 FirewallManager

> Kurumsal güvenlik duvarı kurallarını merkezi olarak yönetmek için geliştirilmiş, Streamlit tabanlı profesyonel yönetim paneli.

---

## 📌 Proje Hakkında

FirewallManager, şirket ağlarında firewall kurallarını terminal kullanmadan, görsel bir arayüzden yönetmeyi sağlayan açık kaynaklı bir araçtır. `iptables` (Linux) ve `pfctl` (macOS) üzerinde çalışır; kuralları üretir, uygular, izler ve raporlar.

Hedef kitle: sistem yöneticileri, ağ güvenliği ekipleri ve DevOps mühendisleri.

---

## 🚨 Çözdüğü Problemler

| Problem | FirewallManager'ın Çözümü |
|---|---|
| Her sunucuya ayrı ayrı SSH bağlanmak | Merkezi panel üzerinden tüm kuralları yönet |
| `iptables` syntax hatası yapma riski | Form tabanlı kural oluşturucu, validasyon ile |
| Kimin ne zaman ne değiştirdiği belirsiz | Otomatik değişiklik geçmişi ve audit log |
| Yanlış kural uygulayıp sistemi kesmek | Dry-run (simülasyon) modu — önce test et |
| Kural çakışmalarını fark edememe | Otomatik çakışma tespiti ve uyarı sistemi |
| Geri alma (rollback) zorluğu | Her değişiklik öncesi otomatik backup |

---

## ✨ Özellikler

### 📋 Kural Yönetimi
- IP adresi, port, protokol ve aksiyon (ALLOW / DENY / LOG) bazlı kural oluşturma
- Kural önceliklendirme (sürükle-bırak sıralama)
- Toplu kural silme ve düzenleme
- Kural grupları ve etiket sistemi

### ▶️ Uygulama Motoru
- **Dry-run modu** — Kuralı uygulamadan önce simüle et, diff görünümü ile ne değişeceğini gör
- Gerçek `iptables` / `pfctl` komut üretimi ve çalıştırma
- Uygulama öncesi otomatik yedek alma
- Tek tıkla rollback

### 📡 Trafik İzleme
- Anlık aktif bağlantı listesi (`/proc/net/` veya `scapy`)
- Engellenen IP adresleri ve nedenleri
- Hangi kuralın tetiklendiğini gerçek zamanlı gösterme
- Şüpheli trafik uyarıları

### 📊 İstatistik & Dashboard
- En çok tetiklenen kurallar
- Engelleme / izin verme oranı grafikleri
- Saatlik / günlük trafik dağılımı
- Risk skoru hesaplama

### 📄 Log Analizi
- `/var/log/syslog` ve `iptables` log parse
- Arama ve filtreleme
- IP bazlı log geçmişi
- Şüpheli IP tespiti (aynı IP'den çok sayıda deneme)

### 📤 Import / Export
- Kural seti JSON ve CSV olarak dışa aktar
- Başka sistemden kural içe aktar
- Aylık/haftalık denetim raporu (HTML / JSON)

---

## 🏗️ Proje Yapısı

```
firewall_manager/
├── main.py                    # Streamlit giriş noktası
├── requirements.txt
├── core/
│   ├── __init__.py
│   ├── rule_engine.py         # Kural CRUD + validasyon
│   ├── iptables_adapter.py    # iptables/pfctl komut üretici
│   ├── traffic_monitor.py     # Anlık bağlantı izleme
│   └── log_parser.py          # Firewall log okuyucu
├── ui/
│   ├── __init__.py
│   └── components.py          # Streamlit UI bileşenleri
└── utils/
    ├── __init__.py
    ├── rule_store.py           # JSON dosyasına kayıt
    ├── validator.py            # IP/port validasyon
    └── backup.py              # Otomatik yedekleme
```

---

## 🖥️ Arayüz Sekmeleri

| Sekme | Açıklama |
|---|---|
| 📋 **Kurallar** | Kural tablosu — ekle, düzenle, sil, önceliklendir |
| ▶️ **Uygula** | Dry-run simülasyonu + gerçek uygulama, diff görünümü |
| 📡 **Trafik** | Anlık bağlantı listesi, engellenen IP'ler |
| 📊 **İstatistik** | En çok tetiklenen kurallar, trafik grafikleri |
| 📄 **Loglar** | Log akışı, filtreleme, şüpheli IP tespiti |

---

## ⚙️ Gereksinimler

### Sistem
- Python 3.10+
- Linux (iptables) veya macOS (pfctl)
- `sudo` yetkisi (kural uygulama için)

### Python Bağımlılıkları

```txt
streamlit>=1.32.0
pandas>=2.1
plotly>=5.18
scapy>=2.5.0
psutil>=5.9.0
```

---

## 🚀 Kurulum

```bash
# 1. Repoyu klonla
git clone https://github.com/kullaniciadi/firewall-manager.git
cd firewall-manager

# 2. Bağımlılıkları kur
pip install -r requirements.txt

# 3. Uygulamayı başlat
streamlit run main.py
```

> ⚠️ Kural uygulama özelliği için `sudo` yetkisi gereklidir. Dry-run modu yetki gerektirmez.

---

## 🔒 Güvenlik Notları

- Gerçek kural uygulaması sadece yetkili kullanıcılar tarafından yapılabilir
- Her uygulama öncesi mevcut kural seti otomatik olarak yedeklenir
- Dry-run modu varsayılan olarak açıktır, gerçek uygulama için onay adımı bulunur
- Tüm değişiklikler `audit.log` dosyasına tarih/saat damgasıyla kaydedilir

---

## 📸 Ekran Görüntüleri

> *(Geliştirme aşamasında eklenecek)*

---

## 🗺️ Yol Haritası

- [x] Proje mimarisi ve modül tasarımı
- [ ] Kural motoru ve validasyon
- [ ] iptables adapter
- [ ] Streamlit UI — Kurallar sekmesi
- [ ] Dry-run motoru
- [ ] Trafik izleme modülü
- [ ] Log parser
- [ ] İstatistik dashboard
- [ ] Import / Export
- [ ] Kullanıcı yetkilendirme sistemi
- [ ] Çoklu sunucu desteği

---





