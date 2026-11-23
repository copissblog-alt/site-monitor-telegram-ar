# مراقب مواقع ينبّهك على تيليجرام (Python)

ملف Python واحد، بلا أي مكتبة خارجية، يفحص مواقعك ومنافذ سيرفراتك كل دقيقة، ويرسل لك على تيليجرام حين يتوقف موقع، وحين يعود، وقبل انتهاء شهادة SSL. وترسل له `/status` فيرد بحالة كل شيء.

شرح المشروع كاملاً، وكيف بُني واختُبر، على قيد: **https://qeeid.com/python-website-monitor-telegram-alerts-source-code/**

## المزايا

- فحص HTTP: رمز الحالة المتوقع، وكلمة يجب أن تظهر في الصفحة، وزمن الرد
- فحص منفذ TCP: قاعدة بيانات، SSH، بريد
- تنبيه بانتهاء شهادة SSL قبل 14 يوماً، مرة واحدة في اليوم
- **لا إنذارات كاذبة:** محاولة ثانية داخل الجولة، ثم جولتان فاشلتان متتاليتان قبل التنبيه
- رسالة عودة مع مدة التوقف
- `/status` في تيليجرام: الحالة الآن، ونسبة العمل خلال 24 ساعة، ومتوسط زمن الرد. لا يرد إلا على محادثتك
- ملخص يومي في الساعة التي تختارها
- لا تضيع رسالة: إن تعذر الوصول إلى تيليجرام تبقى الرسائل في صندوق وتُرسل لاحقاً
- يفحص المواقع بالتوازي: 20 موقعاً بطيئاً في ثانيتين بدل 20 ثانية
- النتائج في SQLite، وتُحذف الأقدم من 30 يوماً تلقائياً

## المتطلبات

Python 3.11 أو أحدث (موجود في Ubuntu 24.04 وDebian 12). لا شيء آخر.

## التشغيل

1. أنشئ بوتاً من [@BotFather](https://t.me/BotFather) بالأمر `/newbot` وانسخ التوكن.
2. أرسل أي رسالة لبوتك، ثم افتح `https://api.telegram.org/bot<التوكن>/getUpdates` وانسخ رقم `chat.id`.
3. انسخ `config.example.toml` إلى `config.toml` وضع التوكن والرقم ومواقعك.
4. جرّب:

```bash
python3 monitor.py test-telegram   # تصلك رسالة تجربة
python3 monitor.py once            # جولة فحص واحدة
python3 monitor.py status          # الحالة في الطرفية
```

## التشغيل الدائم

**خدمة systemd (الأفضل):**

```bash
sudo useradd --system --no-create-home monitor
sudo mkdir -p /opt/site-monitor && sudo cp monitor.py config.toml /opt/site-monitor/
sudo chown -R monitor:monitor /opt/site-monitor && sudo chmod 600 /opt/site-monitor/config.toml
sudo cp deploy/site-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now site-monitor
journalctl -u site-monitor -f
```

**أو cron كل دقيقة** (بلا أمر `/status`):

```
* * * * * cd /opt/site-monitor && python3 monitor.py once >> monitor.log 2>&1
```

> شغّل المراقب على سيرفر **غير** السيرفر الذي تراقبه، أو على جهاز في البيت: إن توقف السيرفر كله لن يستطيع أن يخبرك.

## الاختبارات

```bash
python3 -m unittest -v tests/test_monitor.py
```

14 اختباراً بموقع محلي وخادم تيليجرام مزيف وشهادة SSL تنتهي بعد 5 أيام: العتبة والعودة، والكلمة المفقودة، و404، والمهلة، وDNS، والمنفذ المغلق والمفتوح، وتنبيه الشهادة مرة واحدة، والشهادة غير الموثوقة، وصندوق الرسائل حين يتعطل تيليجرام، و`/status` للمالك فقط، وهروب HTML.

## الترخيص

MIT — استعمله وعدّله كما تشاء.

---

**Website & port monitor with Telegram alerts in a single stdlib-only Python file**: HTTP/keyword/TCP/SSL-expiry checks, false-alarm protection, recovery duration, `/status` command, daily summary, persistent outbox. MIT licensed.
