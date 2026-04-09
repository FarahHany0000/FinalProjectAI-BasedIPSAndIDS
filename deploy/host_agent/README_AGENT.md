# IDS Host Agent — Deployment Package
# دليل تثبيت عميل المراقبة + محاكاة الهجوم

## 📦 محتويات المجلد

| File | الوظيفة |
|------|---------|
| `host_agent.py` | الـ Agent الأساسي — بيراقب الجهاز ويبعت البيانات للسيرفر |
| `alert_ui.py` | نافذة التحذير الأمني (بتقفل الشاشة لحد ما الأدمن يدخل الباسورد) |
| `host_attack_simulation.py` | محاكاة هجمات للاختبار (6 أنواع مختلفة) |
| `config.ini` | إعدادات الاتصال بالسيرفر |
| `requirements.txt` | المكتبات المطلوبة |
| `install_agent.py` | سكريبت التثبيت التلقائي |

---

## 🚀 خطوات التشغيل (3 خطوات بس)

### الخطوة 1: تثبيت البيئة

**افتح CMD أو PowerShell في مجلد `host_agent` وشغّل:**

```bash
python install_agent.py
```

ده هيعمل كل حاجة تلقائي (venv + تثبيت المكتبات).

**أو لو عايز تعمل يدوي:**
```bash
cd host_agent
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### الخطوة 2: ظبط IP السيرفر

**مهم جداً:** افتح ملف `config.ini` وغيّر `server_host` لـ IP جهاز السيرفر:

```ini
[agent]
server_host = 192.168.1.6       ; ← حط IP السيرفر هنا
server_port = 5000
agent_key = changeme
```

**إزاي تعرف IP السيرفر؟**
- على جهاز السيرفر (اللي شغّال عليه الـ Backend): افتح CMD واكتب `ipconfig`
- خد الـ IPv4 Address (مثلاً `192.168.1.6`)
- لو الجهازين على نفس الشبكة، سيب `AUTO` وهيلاقيه لوحده

### الخطوة 3: شغّل الـ Agent

```bash
venv\Scripts\activate
python host_agent.py
```

**أو لو عايز تحدد السيرفر من الأمر مباشرة:**
```bash
python host_agent.py --server 192.168.1.6:5000
```

**لو شغّال صح هتشوف كده:**
```
==================================================
  Host IDS Agent
  Host:     PC-NAME (192.168.x.x)
  Agent ID: xxxxxxxx...
  Server:   http://192.168.1.6:5000/api/agent/host-report
  Window:   5s  |  Interval: 10s
==================================================
[HEARTBEAT] Server is UP (attempt 1)
[REGISTER] registered_new (approved: True)
[OK] Threat=Normal | Action=No Action | logons=0 pkts=50 files=3
```

---

## 🌐 ربط الأجهزة ببعض (مهم!)

### على جهاز السيرفر (عندك):
1. شغّل الـ Backend: `python app.py` (من مجلد `project/backend`)
2. شغّل الـ Frontend: `npm run dev` (من مجلد `project/frontend`)
3. اعرف الـ IP بتاعك: `ipconfig` ← خد IPv4 Address

### على جهاز صاحبك:
1. انسخ مجلد `host_agent` كله على جهازه (فلاشة أو Share)
2. شغّل `python install_agent.py`
3. عدّل `config.ini` ← حط IP جهازك (السيرفر)
4. شغّل `python host_agent.py`

### شروط الاتصال:
- **الجهازين لازم يكونوا على نفس الشبكة** (نفس الراوتر / Hotspot / LAN)
- **Port 5000 لازم يكون مفتوح** على جهاز السيرفر
- لو الـ Firewall بيمنع، افتح Port 5000:
  ```bash
  netsh advfirewall firewall add rule name="IDS Backend" dir=in action=allow protocol=TCP localport=5000
  ```

### طريقة سريعة للاختبار بدون راوتر:
1. شغّل **Mobile Hotspot** من جهازك (Settings → Mobile Hotspot)
2. وصّل جهاز صاحبك على الـ Hotspot
3. استخدم IP الـ Hotspot (عادة `192.168.137.1`)

---

## 🔒 إزاي الـ Agent بيشتغل

1. **أول تشغيل** ← بيعمل Hardware Fingerprint فريد للجهاز (CPU + MAC + Serial)
2. **بيسجّل نفسه** في السيرفر تلقائي
3. **كل 10 ثواني** بيجمع بيانات من الجهاز:
   - نشاط الملفات (ملفات جديدة/معدّلة)
   - USB/فلاشات
   - اتصالات الشبكة
   - أوقات الدخول
4. **بيبعت** البيانات للـ AI Model (XGBoost) على السيرفر
5. **لو اكتشف هجوم** ← السيرفر بيبعت أوامر حماية:
   - 🔒 قفل الشاشة
   - ⛔ تعطيل USB
   - ⚠️ نافذة تحذير أمني (محتاجة باسورد أدمن)
   - 🔪 إيقاف العمليات المشبوهة
6. **الأدمن يدخل الباسورد** → كل حاجة ترجع عادي

### نافذة التحذير:
- **مش هتقفل** بدون باسورد الأدمن
- **فوق كل النوافذ** — مفيش حاجة تقدر تغطيها
- باسورد الأدمن الافتراضي: `admin123`

---

## 🎯 اختبار بمحاكاة الهجوم

**لازم الـ Agent يكون شغّال الأول!**

افتح Terminal تاني وشغّل:
```bash
venv\Scripts\activate
python host_attack_simulation.py
```

القائمة:
| # | نوع الهجوم | الوصف |
|---|-----------|-------|
| 1 | 💾 Data Exfiltration | سرقة ملفات عبر USB |
| 2 | 🔥 IT Sabotage | تدمير ملفات بالجملة |
| 3 | 🕵️ Espionage | تجسس + وصول شبكي |
| 4 | 💰 Fraud | وصول غير مصرح لبيانات مالية |
| 5 | 🌐 System Abuse | إغراق الشبكة |
| 6 | ☠️ Combined Attack | كل الهجمات مع بعض (أقوى سيناريو) |
| 7 | 👤 Normal Baseline | نشاط عادي (المفروض ما يتكشفش) |

> **آمن تماماً**: كل الملفات والتغييرات بتتنضف تلقائي بعد كل اختبار.

---

## ⚙️ مرجع الإعدادات

### config.ini:
```ini
[agent]
server_host = 192.168.1.6   ; IP السيرفر (أو AUTO للبحث التلقائي)
server_port = 5000           ; بورت السيرفر (ثابت)
agent_key = changeme         ; مفتاح التوثيق (لازم يطابق السيرفر)
interval = 10                ; ثواني بين كل فحص
window = 5                   ; مدة جمع البيانات (ثواني)
```

### أوامر إضافية:
```bash
python host_agent.py --server 192.168.1.6:5000    # تحديد سيرفر مباشرة
python host_agent.py --interval 5                   # فحص كل 5 ثواني
```

---

## 🔧 حل المشاكل

| المشكلة | الحل |
|---------|------|
| `ConnectionError` | تأكد من IP السيرفر وإن Port 5000 مفتوح |
| `Pending approval` | الأدمن لازم يوافق على الجهاز من الـ Dashboard |
| الـ Alert بيظهر بدون سبب | ده false positive — أدخل الباسورد `admin123` |
| `pip install` مش شغّال | تأكد إنك في الـ venv: `venv\Scripts\activate` |
| pywebview مش شغّال | شغّل: `pip install pywebview>=4.0` |
| `rejected` | امسح ملف `.agent_id` وأعد التشغيل |
| الجهاز مش ظاهر في الـ Dashboard | تأكد إن الجهازين على نفس الشبكة |

---

## 🛑 إيقاف الـ Agent
اضغط `Ctrl+C` — بيقفل بأمان وبيرجّع كل إعدادات الحماية لوضعها الطبيعي.

---

## 📋 المتطلبات
- **Python 3.8+** (مجرّب على 3.12)
- **Windows 10/11**
- اتصال شبكة بجهاز السيرفر
- المكتبات: `psutil`, `requests`, `pywebview` (بتتثبت تلقائي)

---

## 🔐 ملاحظات أمنية
- كل جهاز بيعمل **بصمة Hardware فريدة** — نسخ الملفات لجهاز تاني مش هيشتغل بنفس الـ ID
- ملف `.agent_id` بيتعمل أوتوماتيك أول تشغيل — **متنسخوش** بين الأجهزة
- باسورد الأدمن الافتراضي: `admin123`
- مفتاح التوثيق `agent_key` لازم يكون نفسه في `config.ini` وفي السيرفر
