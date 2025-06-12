from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import CallbackContext
import re
import logging

_secure_logger = logging.getLogger(__name__)

# پنل تعاملی شخصی‌سازی شده با دسترسی محدود و اعتبارسنجی دقیق ورودی‌ها
async def _secure_panel_start(_msg_update: Update, _ctx: CallbackContext):
    _caller_id = _msg_update.message.from_user.id
    _storage = _ctx.bot_data
    _grp_owners = _storage.get('grp_owners_map', {})
    _grp_admins = _storage.get('grp_admins_map', {})

    _message_text = "پنل مدیریت امن:\n"
    _btns = []

    # گروه‌هایی که درخواست‌کننده مالک آن‌هاست
    _owned_groups = [g for g, o in _grp_owners.items() if o == _caller_id]
    if _owned_groups:
        _message_text += "\nشما مالک گروه‌های زیر هستید و می‌توانید ادمین‌ها را مدیریت کنید:\n"
        for _g_id in _owned_groups:
            _btns.append([InlineKeyboardButton(f"مدیریت ادمین‌های گروه {_g_id}", callback_data=f"secure_admin_manage:{_g_id}")])

    # گروه‌هایی که درخواست‌کننده ادمین است اما مالک نیست
    _admin_groups = [g for g, admins in _grp_admins.items() if _caller_id in admins and g not in _owned_groups]
    if _admin_groups:
        _message_text += "\nشما ادمین بات در گروه‌های زیر هستید:\n"
        for _g_id in _admin_groups:
            _btns.append([InlineKeyboardButton(f"نمایش کاربران مشکوک گروه {_g_id}", callback_data=f"secure_show_suspicious:{_g_id}")])

    # گزینه ثبت گزارش برای تمام کاربران
    _btns.append([InlineKeyboardButton("ثبت گزارش تخلف", callback_data="secure_report_menu")])

    _markup = InlineKeyboardMarkup(_btns)
    await _msg_update.message.reply_text(_message_text, reply_markup=_markup)

# هندلر کال‌بک با تایید دسترسی و جلوگیری از داده‌های ناخوانا برای جلوگیری از سوءاستفاده
async def _secure_panel_callback(_update: Update, _ctx: CallbackContext):
    _query = _update.callback_query
    await _query.answer()
    _user_id = _query.from_user.id
    _data = _query.data

    _storage = _ctx.bot_data
    _owners = _storage.get('grp_owners_map', {})
    _admins = _storage.get('grp_admins_map', {})
    _users_info = _storage.get('users_records', {})
    _reports = _storage.get('reports_archive', {})

    # مدیریت ایمن ادمین گروه توسط مالک
    if _data.startswith("secure_admin_manage:"):
        try:
            _grp_id = int(_data.split(":")[1])
        except ValueError:
            await _query.edit_message_text("داده نامعتبر است.")
            return
        if _owners.get(_grp_id) != _user_id:
            await _query.answer("دسترسی ندارید، شما مالک این گروه نیستید.", show_alert=True)
            return

        _current_admins = _admins.get(_grp_id, set())
        _response = f"ادمین‌های فعلی گروه {_grp_id} به شرح زیر است:\n"
        for _a_id in _current_admins:
            _response += f"- {_a_id}\n"
        _response += "\nآیدی تلگرام ادمین جدید را ارسال کنید یا 'لغو' برای خروج."

        _ctx.user_data['sec_admin_group'] = _grp_id
        _ctx.user_data['sec_admin_mode'] = 'add'
        await _query.edit_message_text(_response)

    # نمایش کاربران مشکوک با حفظ حریم خصوصی و محدودیت دسترسی
    elif _data.startswith("secure_show_suspicious:"):
        try:
            _grp_id = int(_data.split(":")[1])
        except ValueError:
            await _query.edit_message_text("داده نامعتبر است.")
            return
        if _user_id not in _admins.get(_grp_id, set()) and _user_id != _owners.get(_grp_id):
            await _query.answer("دسترسی کافی ندارید.", show_alert=True)
            return
        _lines = []
        for _uid, _info in _users_info.items():
            if _info.get('flagged', False):
                _uname = _info.get('username', 'ناشناخته')
                _scr = _info.get('score', 0)
                _rsns = ', '.join(_info.get('flag_reasons', []))
                _lines.append(f"ID:{_uid} | @{_uname} | امتیاز: {_scr} | دلایل: {_rsns}")
        if not _lines:
            await _query.edit_message_text("کاربر مشکوک یافت نشد.")
        else:
            _txt = f"کاربران مشکوک گروه {_grp_id}:\n" + "\n".join(_lines)
            await _query.edit_message_text(_txt)

    # منوی ثبت و مشاهده گزارش برای کاربران معمولی
    elif _data == "secure_report_menu":
        _buttons = [
            [InlineKeyboardButton("ثبت گزارش جدید", callback_data="secure_report_new")],
            [InlineKeyboardButton("مشاهده گزارش‌های من", callback_data="secure_report_view")]
        ]
        await _query.edit_message_text("پنل گزارش‌ها:", reply_markup=InlineKeyboardMarkup(_buttons))

    elif _data == "secure_report_new":
        await _query.edit_message_text("متن گزارش تخلف را ارسال کنید:")
        _ctx.user_data['reporting'] = True

    elif _data == "secure_report_view":
        _user_reports = _reports.get(_user_id, [])
        if not _user_reports:
            await _query.edit_message_text("گزارشی ثبت نکرده‌اید.")
        else:
            _output = "گزارش‌های شما:\n"
            for idx, rep in enumerate(_user_reports, 1):
                _clean = re.sub(r'[^\w\s\-.,!?@:/]', '', rep)
                _output += f"{idx}. {_clean}\n"
            await _query.edit_message_text(_output)

    else:
        await _query.answer()

# دریافت متن گزارش با کنترل وضعیت و تایید ورودی پاکسازی شده
async def _secure_report_text_handler(_update: Update, _ctx: CallbackContext):
    if _ctx.user_data.get('reporting'):
        _user_id = _update.message.from_user.id
        _text = _update.message.text
        if _text.strip().lower() == 'لغو':
            _ctx.user_data['reporting'] = False
            await _update.message.reply_text("فرآیند گزارش لغو شد.")
            return
        _reports = _ctx.bot_data.setdefault('reports_archive', {})
        _reports.setdefault(_user_id, []).append(_text.strip())
        _ctx.user_data['reporting'] = False
        await _update.message.reply_text("گزارش شما با موفقیت ثبت شد. متشکریم.")
    else:
        # دیگر پیام‌ها را مدیریت یا رد کنید
        pass
