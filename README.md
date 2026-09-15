# SSRFScope 0.2.0

محرك كشف SSRF عملي مبني بالكامل على مكتبة Python القياسية، ومخصص للاختبار المصرّح به داخل مختبرات الجامعة أو بيئات يملكها فريق الاختبار.

> **تنبيه أخلاقي:** لا تستخدم الأداة ضد أنظمة لا تملكها أو لا تملك تصريحاً مكتوباً لاختبارها. الإعدادات الافتراضية محافظة، ولا تفحص Cloud Metadata تلقائياً.

## المكونات

```text
ssrfscope.py          المحرك والأوامر الرئيسية
lab_server.py         مختبر SSRF محلي معزول
README.md             دليل الاستخدام
 tests/               اختبارات Unit Tests
```

لا توجد تبعيات خارجية. المتطلبات: Python 3.9 أو أحدث.

## لغة الأداة والتقرير

واجهة الأوامر والقائمة التفاعلية باللغة الإنجليزية، بينما يتم إنشاء التقرير HTML باللغة العربية حتى يكون مناسباً للتسليم الجامعي.

## الوضع التفاعلي والشعار

يمكن تشغيل الأداة بدون معاملات:

```bash
python3 ssrfscope.py
```

ستعرض الأداة شعار SSRFScope، ثم تطلب عنوان الموقع أو IP، وبعد ذلك تظهر قائمة. إذا أدخلت IP أو رابطاً بدون Query Parameter ثم اخترت Full scan، ستطلب الأداة منك تحديد مصدر الحقن: Parameter أو Header أو JSON أو Form أو Raw Request file. يجب أن يكون الهدف هو نقطة SSRF فعلية، وليس عنوان الخادم العام فقط.

مثال صحيح:

```text
http://host/fetch?url=x
```

ستظهر قائمة:

1. فحص شامل
2. فحص مركّز
3. تشغيل OOB Listener
4. إنشاء تقرير
5. تشغيل DNS Rebinding Lab
6. تغيير الهدف
0. خروج

الشعار الأصلي المستخدم في التقارير محفوظ في:

```text
logo.png
```

## أسلوب الأوامر

واجهة سطر الأوامر مصممة بأسلوب قريب من Nmap: أوامر واضحة، `--help` منظم، Target في الأمر، خيارات إخراج مختصرة، ونتائج مرتبة. لكنها ليست Port Scanner؛ يجب تحديد Endpoint ونقطة حقن SSRF.

```text
scan          فحص شامل لنقاط الحقن
probe         فحص مركّز
report        إنشاء تقرير HTML من JSON
oob           خادم OOB مستقل وإدارة الأحداث
dns-rebind    خادم DNS تعليمي محدود لعناوين المختبر
```

خيارات الإخراج المختصرة:

```text
-oJ FILE      حفظ JSON
-oH FILE      حفظ تقرير HTML عربي
-v            تشغيل السجل التفصيلي
```

مثال:

```bash
python3 ssrfscope.py scan \\
  http://127.0.0.1:8787/fetch?url=x \\
  --param url \\
  --payload http://127.0.0.1:8788/ \\
  -oJ scan.json -oH scan.html
```

## التشغيل السريع في المختبر

شغّل المختبر:

```bash
python3 lab_server.py
```

الخدمات:

```text
التطبيق التجريبي:     http://127.0.0.1:8787
الخدمة الداخلية:      http://127.0.0.1:8788
جامع OOB في المختبر:  http://127.0.0.1:8789
```

ثم نفّذ فحص SSRF:

```bash
python3 ssrfscope.py scan \
  'http://127.0.0.1:8787/fetch?url=x' \
  --payload 'http://127.0.0.1:8788/' \
  --save first-scan.json
```

سيتم إنشاء التقرير تلقائياً:

```text
first-scan.json
first-scan.html
```

## فحص Parameters وHeaders

فحص Parameter محدد:

```bash
python3 ssrfscope.py probe \
  'https://authorized.example/fetch?url=https%3A%2F%2Fexample.org' \
  --param url \
  --payload 'http://127.0.0.1:8788/'
```

في `scan` يتم اكتشاف Query Parameters الموجودة في الرابط تلقائياً إذا لم تستخدم `--param`.

فحص Header مع Header ثابت للمصادقة:

```bash
python3 ssrfscope.py probe \
  'https://authorized.example/proxy' \
  --header-target X-Target-URL \
  --set-header 'Authorization=Bearer REDACTED' \
  --payload 'http://127.0.0.1:8788/'
```

لا تضع Tokens حقيقية داخل ملفات المشروع أو أوامر محفوظة في Git.

## JSON وForm Body

JSON top-level أو nested:

```bash
python3 ssrfscope.py probe \
  'http://127.0.0.1:8787/api/fetch' \
  --body-json '{"options":{"redirect":{"url":"x"}}}' \
  --body-json-field options.redirect.url \
  --method POST \
  --payload 'http://127.0.0.1:8788/'
```

في `scan` يمكن اكتشاف الحقول scalar تلقائياً:

```bash
python3 ssrfscope.py scan \
  'http://127.0.0.1:8787/api/fetch' \
  --body-json '{"url":"x","mode":"preview"}' \
  --method POST \
  --payload 'http://127.0.0.1:8788/'
```

Form:

```bash
python3 ssrfscope.py probe \
  'http://127.0.0.1:8787/form-fetch' \
  --body-form 'url=x&mode=preview' \
  --body-form-field url \
  --method POST \
  --payload 'http://127.0.0.1:8788/'
```

## استيراد HTTP Request من Burp أو ملف نصي

أنشئ ملفاً مثل `request.txt`:

```http
POST /api/fetch HTTP/1.1
Host: 127.0.0.1:8787
Content-Type: application/json
X-Lab-Header: demo

{"url":"x","mode":"preview"}
```

ثم شغّل:

```bash
python3 ssrfscope.py scan \
  --request-file request.txt \
  --all-request-headers \
  --payload 'http://127.0.0.1:8788/' \
  --save request-scan.json
```

يتم اكتشاف method وHost وContent-Type وBody وحقول JSON. Headers الحساسة مثل `Authorization` و`Cookie` لا تُحقن تلقائياً عند استخدام `--all-request-headers`؛ حددها يدوياً إذا كان الاختبار مصرحاً.

## Blind SSRF وOOB

### خادم OOB مستقل

في نافذة منفصلة:

```bash
python3 ssrfscope.py oob start \
  --bind 127.0.0.1 \
  --port 8790 \
  --events-file oob-events.json
```

نفّذ الفحص باستخدام callback:

```bash
python3 ssrfscope.py probe \
  'http://127.0.0.1:8787/fetch?url=x' \
  --param url \
  --oob-template 'http://127.0.0.1:8790/callback/{token}' \
  --save oob-scan.json
```

عرض الأحداث:

```bash
python3 ssrfscope.py oob events \
  --events-file oob-events.json \
  --pretty
```

مسح الأحداث:

```bash
python3 ssrfscope.py oob clear --events-file oob-events.json
```

يولّد SSRFScope Token مختلفاً لكل محاولة ويحفظه في `oob_token` و`payload_template` داخل JSON.

## DNS Rebinding التعليمي

هذه الميزة مخصصة لمختبر معزول فقط. الخادم يقبل عناوين private/loopback/reserved فقط، ولا يقبل IP عام عشوائي.

شغّل DNS server:

```bash
python3 ssrfscope.py dns-rebind start \
  --bind 127.0.0.1 \
  --port 53535 \
  --first-ip 198.51.100.10 \
  --second-ip 127.0.0.1 \
  --switch-after 1 \
  --ttl 1
```

اختبر تسلسل الإجابات:

```bash
python3 ssrfscope.py dns-rebind query example.test \
  --server 127.0.0.1 \
  --port 53535 \
  --count 3
```

الناتج المتوقع يكون قريباً من:

```json
{
  "answers": [
    "198.51.100.10",
    "127.0.0.1",
    "127.0.0.1"
  ]
}
```

هذه أداة تعليمية لشرح تغير DNS responses، وليست طريقة لتجاوز أنظمة خارج نطاق المختبر.

## التقارير واكتشاف النتائج الجديدة

بعد كل `scan` أو `probe` ينشئ البرنامج JSON وHTML تلقائياً. لتعطيل HTML:

```bash
--no-auto-report
```

إعادة إنشاء التقرير:

```bash
python3 ssrfscope.py report first-scan.json --output first-scan.html
```

مقارنة فحصين:

```bash
python3 ssrfscope.py scan \
  'http://127.0.0.1:8787/fetch?url=x' \
  --param url \
  --payload 'http://127.0.0.1:8788/' \
  --save second-scan.json \
  --compare first-scan.json
```

يعرض التقرير:

- اكتشافات جديدة
- نتائج اختفت أو تم حلها
- نتائج زادت شدتها
- توقيعات جديدة ظهرت

هذه مقارنة بين فحصين، وليست قاعدة بيانات CVE أو ضماناً باكتشاف جميع أنواع الثغرات.

## المنهجية

لكل نقطة حقن يتم إنشاء Baseline باستخدام:

```text
ssrfscope-baseline
```

ثم تتم مقارنة كل Payload مع Baseline باستخدام:

- تغيّر HTTP status
- توقيعات محتوى الخدمات الداخلية
- تغيّر body length
- تغيّر response time
- اختلاف أخطاء الشبكة
- عنوان الصفحة وContent-Type

التصنيفات:

```text
possible-ssrf   score >= 3
interesting     score = 2
inconclusive    score < 2
```

النتيجة Heuristic وتحتاج تحققاً يدوياً داخل النطاق المصرّح.

## Logs وProfiles

تفعيل السجل:

```bash
python3 ssrfscope.py probe URL \
  --param url \
  --payload 'http://127.0.0.1:8788/' \
  --log-file scan.log \
  --verbose
```

مثال Profile:

```json
{
  "headers": {
    "Authorization": "Bearer REDACTED"
  },
  "cookies": {
    "session": "REDACTED"
  }
}
```

تشغيله:

```bash
--profile profile.json
```

## الاختبارات

```bash
python3 -m py_compile ssrfscope.py lab_server.py
python3 -m unittest discover -s tests -v
```

## حدود الاستخدام

- لا توجد قراءة تلقائية لأسرار Cloud Metadata.
- لا يوجد تنفيذ أوامر عن بعد.
- لا يوجد استخراج Credentials.
- لا يتم اتباع Redirects افتراضياً.
- لا توجد تبعيات خارجية.
- لا تدّعي الأداة اكتشاف كل SSRF أو كل CVEs.
- لا تستخدم `--bind 0.0.0.0` إلا داخل شبكة مختبر معزولة وتحت تصريح واضح.

## المكتبات المستخدمة وأهميتها

المشروع مبني بالكامل على **Python Standard Library** ولا يحتاج إلى تثبيت مكتبات خارجية مثل `requests` أو `scapy`.

### مكتبات الواجهة والبيانات

| المكتبة | الاستخدام داخل المشروع | الأهمية والمستفيد |
|---|---|---|
| `argparse` | إنشاء أوامر `scan` و`probe` و`report` و`oob` و`dns-rebind` | تجعل الواجهة احترافية وقريبة من أدوات مثل Nmap، وتفيد المستخدم ومختبر الاختراق |
| `json` | قراءة JSON Body وProfiles وحفظ النتائج والأحداث | ضرورية لاختبار APIs الحديثة وإنتاج تقارير قابلة للمعالجة |
| `dataclasses` | تنظيم Target وResponse Snapshot | تجعل الكود أسهل في القراءة والصيانة |
| `typing` | Type Hints مثل `List` و`Dict` و`Optional` | تزيد وضوح الكود وتساعد الطالب أثناء المناقشة والتطوير |
| `datetime` | تسجيل وقت الفحص ووقت OOB callback | مهمة للتوثيق ومقارنة الفحوصات |
| `os` و`sys` | التعامل مع الملفات والمسارات ومتغيرات التشغيل وExit Codes | تساعد في تشغيل الأداة على Windows وLinux |
| `logging` | إنشاء ملفات Log مع `--verbose` و`--log-file` | تفيد في تتبع الطلبات والأخطاء أثناء الاختبار |

### مكتبات HTTP وتحليل الروابط

| المكتبة | الاستخدام داخل المشروع | الأهمية |
|---|---|---|
| `urllib.request` | إرسال GET وPOST وHTTPS Requests | محرك الإرسال الرئيسي بدون تبعيات خارجية |
| `urllib.error` | التقاط `HTTPError` و`URLError` ومشاكل الاتصال | أخطاء الشبكة قد تكون دليلاً على SSRF، كما تمنع توقف الأداة |
| `urllib.parse` | تحليل وتعديل Query Parameters وForm Body والروابط | تتيح حقن Payloads بطريقة صحيحة مع URL Encoding |
| `http.client` | التعامل مع أخطاء HTTP منخفضة المستوى | يحسن ثبات محرك الفحص |
| `ssl` | التحقق من TLS ودعم `--insecure` للمختبر | يسمح بفحص HTTPS وشهادات Self-Signed داخل بيئة اختبار |
| `http.server` | تشغيل OOB Listener وخدمات المختبر | يسمح باختبار Blind SSRF محلياً بدون خدمة خارجية |

### مكتبات التحليل والتزامن

| المكتبة | الاستخدام داخل المشروع | الأهمية |
|---|---|---|
| `re` | اكتشاف توقيعات Redis وElasticsearch وأخطاء الشبكة واستخراج HTML title | تقلل False Positives وتحوّل الاستجابة إلى Finding مفهومة |
| `hashlib` | إنشاء SHA-256 للاستجابة | مقارنة الاستجابات بدون حفظ Body كامل |
| `concurrent.futures` | تشغيل Payloads بالتوازي | يسرّع الفحص ويستفيد منه Pentesters وفرق AppSec |
| `threading` | تشغيل الخوادم وحماية ملف أحداث OOB | يسمح باستقبال أكثر من اتصال في الوقت نفسه |
| `time` | قياس زمن الاستجابة وتطبيق Delay | يساعد على كشف الفروقات الزمنية وتقليل ضغط الفحص |
| `uuid` | إنشاء OOB Token فريد لكل محاولة | يربط Callback بالـ Payload الصحيح |

### مكتبات التقرير والشعار

| المكتبة | الاستخدام داخل المشروع | الأهمية |
|---|---|---|
| `html` | عمل Escape للنصوص قبل وضعها في HTML | يحمي التقرير من HTML Injection عند عرض الاستجابات |
| `base64` | تضمين `logo.png` داخل تقرير HTML | يجعل التقرير مستقلاً ولا يحتاج إلى تحميل الشعار من الإنترنت |

### مكتبات DNS والسلامة

| المكتبة | الاستخدام داخل المشروع | الأهمية |
|---|---|---|
| `socket` | إنشاء UDP DNS Lab وإرسال DNS Queries | الأساس في تنفيذ DNS Rebinding التعليمي |
| `struct` | قراءة وإنشاء Binary DNS Packets | ضرورية للتعامل مع بنية بروتوكول DNS |
| `ipaddress` | التحقق من أن عناوين DNS Lab خاصة أو Loopback أو Reserved | تقلل خطر استخدام DNS Lab ضد عناوين عامة |

### مكتبات الاختبارات

| المكتبة | الاستخدام | الأهمية |
|---|---|---|
| `unittest` | Unit Tests للمحرك | يثبت أن الوظائف الأساسية تعمل قبل التسليم |
| `tempfile` | إنشاء ملفات مؤقتة لاختبار Raw Requests | يجعل الاختبارات معزولة وقابلة لإعادة التشغيل |
| `pathlib` | إدارة مسارات ملفات الاختبارات | يبسط التعامل مع الملفات على أنظمة التشغيل المختلفة |

## من يستفيد من SSRFScope؟

- **طلاب الأمن السيبراني:** لفهم SSRF وHTTP وOOB وDNS Rebinding.
- **مختبرو الاختراق:** لفحص Parameters وHeaders وAPIs داخل نطاق مصرح.
- **مطورو التطبيقات:** لاختبار Endpoints التي تستقبل URLs أو Webhooks.
- **فرق AppSec وDevSecOps:** لمقارنة نتائج الفحوصات وإدراجها في مراحل الاختبار.
- **فرق Cloud Security:** لاكتشاف مؤشرات الوصول غير المقصود إلى الخدمات الداخلية.
- **الجامعات والمدربون:** لعرض سيناريو عملي آمن بدون أسرار أو بيانات حقيقية.

## فائدة الأداة

تجمع SSRFScope في أداة واحدة:

```text
SSRF Detection
Response Heuristics
Blind SSRF / OOB
JSON وForm وHeaders
Raw HTTP Requests
DNS Rebinding Lab
Differential Findings
Arabic HTML Reports
Interactive Menu
```

الأداة ليست Port Scanner عاماً مثل Nmap؛ فهي تحتاج إلى Endpoint ونقطة حقن SSRF، لكنها تستخدم أسلوباً قريباً من Nmap في الأوامر والمساعدة وحفظ النتائج وعرض الحالة.
