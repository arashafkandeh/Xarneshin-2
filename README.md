<a href="/README.md"><img src="https://flagicons.lipis.dev/flags/4x3/gb.svg" alt="English" width="20"/> English</a> | <a href="/README_FA.md"><img src="https://flagicons.lipis.dev/flags/4x3/ir.svg" alt="فارسی" width="20"/> فارسی</a>
<br><br>

<div style="display: flex; justify-content: center; align-items: center; gap: 10px; max-width: 100%;">
    <img src="https://github.com/MeXenon/Xarneshin/blob/main/Preview/main.jpg" alt="Main Preview" style="width: 350px; height: auto; border-radius: 10px;">
    <img src="https://github.com/MeXenon/Xarneshin/blob/main/Preview/other.jpg" alt="Other Preview" style="width: 350px; height: auto; border-radius: 10px;">
</div>

<br>

<div style="display: flex; justify-content: center;">
    <img src="https://github.com/MeXenon/Xarneshin/blob/main/Preview/CLI.png" alt="CLI Preview" style="width: 400px; height: auto; border-radius: 10px;">
</div>

# زرنشین - مدیریت Xray در مرزنشین با Xenon

**زرنشین** یک ابزار قدرتمند برای مدیریت Xray است که هم از طریق رابط وب و هم خط فرمان قابل استفاده است. این ابزار در کنار [مرزنشین](https://github.com/marzneshin/marzneshin) طراحی شده تا مدیریت سرورها را ساده‌تر کند.

---

## ✨ ویژگی‌ها

- **داشبورد وب**: یک پنل مدرن و واکنش‌گرا برای مدیریت نودهای Xray، اینباندها، اوتباندها، DNS و موارد دیگر.
- **ابزار خط فرمان (CLI)**: امکان انجام وظایف مدیریتی مانند تغییر پورت‌ها، تنظیم HTTPS، به‌روزرسانی فایل‌های Geo و کنترل سرویس از طریق CLI.
- **پیکربندی داینامیک**: امکان مدیریت تنظیمات Xray از طریق `ports.json`.
- **تغییر نسخه هسته**: امکان تعویض نسخه Xray به‌صورت آنی.
- **نظارت سیستمی**: نمایش اطلاعات لحظه‌ای درباره CPU، رم، دیسک و شبکه.
- **پشتیبانی از HTTPS**: امکان فعال‌سازی HTTPS برای افزایش امنیت.
- **یکپارچگی کامل**: هماهنگ‌شده با API مرزنشین برای مدیریت بهتر نودها.

---

## 📢 از ما حمایت کنید:

اگر زرنشین برای شما کاربردی و جالب بود، با ستاره‌دار کردن مخزن و مشارکت در توسعه، ما را همراهی کنید:
- **تلگرام**: [t.me/XenonNet](https://t.me/XenonNet) - برای دریافت اخبار و پشتیبانی.
حمایت شما به بهبود این پروژه کمک می‌کند! 🚀

---

## 📦 نصب

تمام مراحل نصب توسط `install.sh` انجام می‌شود—کافی است آن را اجرا کنید.

### پیش‌نیازها

- پایتون 3.6+
- نصب و اجرای مرزنشین.

### مراحل نصب

دستور زیر را اجرا کنید:

```bash
git clone https://github.com/arashafkandeh/Xarneshin-2.git ~/Xenon.xray && cd ~/Xenon.xray && chmod +x install.sh && sudo ./install.sh
```

- این فرآیند شامل:
  - کلون کردن مخزن در `~/Xenon.xray`.
  - ورود به دایرکتوری.
  - اجرایی کردن اسکریپت نصب.

### بررسی وضعیت نصب

```bash
sudo systemctl status xarneshin.service
```

سپس می‌توانید از طریق `http://<your-server-ip>:<flask-port>` (مانند `http://192.168.1.100:42689`) به رابط وب دسترسی داشته باشید.

**🔑 توجه: اطلاعات ورود به زرنشین مشابه مرزنشین است.**

### (اختیاری) فعال‌سازی HTTPS

برای تنظیم HTTPS، دستور زیر را اجرا کنید:

```bash
xarneshin
```

و گزینه **7: تنظیمات HTTPS** را انتخاب کنید.

---

## 🚀 نحوه استفاده

### رابط وب
- **ورود**: از اطلاعات ورود مرزنشین استفاده کنید.
- **مدیریت نودها**: تنظیمات اینباندها، اوتباندها، DNS و مسیریابی را انجام دهید.
- **تغییر نسخه هسته**: نسخه Xray را مستقیماً از پنل تغییر دهید (برای نود محلی).

### ابزار خط فرمان (CLI)
برای اجرای CLI، دستور زیر را وارد کنید:

```bash
xarneshin
```

**دستورات کاربردی:**
- `status`: مشاهده وضعیت سرویس.
- `change-ports`: تغییر پورت‌های Flask یا پنل.
- `update-geofiles`: دانلود فایل‌های geoip/geosite.
- `restart`: راه‌اندازی مجدد سرویس زرنشین.
- `show-address`: نمایش آدرس دسترسی.
- `uninstall`: حذف زرنشین از سیستم.

برای مشاهده دستورات بیشتر:

```bash
xarneshin --help
```

---

## 🙏 تقدیر و تشکر

- [مرزنشین](https://github.com/marzneshin/marzneshin) - پنل مدیریت vpn
- [MeXenon](https://github.com/MeXenon) | [MeArgon تلگرام](https://t.me/MeArgon) - توسعه‌دهنده اصلی زرنشین.
- [XenonNet](https://github.com/XenonNet) - حامی پروژه.

---

**ساخته‌شده با ❤️ توسط تیم Xenon**  
به ما در [تلگرام](https://t.me/XenonNet) بپیوندید و در توسعه زرنشین مشارکت کنید!
