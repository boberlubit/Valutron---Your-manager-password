import flet as ft
import json
import os
import base64
import hashlib
import sys
import random
import string
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import re
from datetime import datetime


# Установите cryptography если нет: pip install cryptography

def main(page: ft.Page):
    # Конфигурация страницы
    page.title = "Vaultron - Secure Password Manager"
    page.theme_mode = "dark"
    page.vertical_alignment = "start"
    page.horizontal_alignment = "center"
    page.padding = 20
    page.window.width = 650
    page.window.height = 700
    page.window.resizable = True
    page.window.maximizable = True

    # Константы
    USER_DATA_FILE = "vaultron_users.json"
    VAULT_FILE_PREFIX = "vaultron_vault_"
    SALT = b'vaultron_salt_2024'

    # Цветовая схема
    PRIMARY_COLOR = "#6C63FF"
    SECONDARY_COLOR = "#4FC3F7"
    ACCENT_COLOR = "#FF4081"
    BACKGROUND_COLOR = "#121212"
    CARD_COLOR = "#1E1E1E"
    TEXT_COLOR = "#FFFFFF"

    # Глобальные переменные
    current_user = None
    fernet = None

    # Функции шифрования
    def generate_key_from_password(password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=SALT,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def encrypt_data(data, password):
        key = generate_key_from_password(password)
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(json.dumps(data).encode())
        return encrypted_data.decode()

    def decrypt_data(encrypted_data, password):
        try:
            key = generate_key_from_password(password)
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_data.encode())
            return json.loads(decrypted_data.decode())
        except:
            return None

    # Функции для работы с данными
    def load_user_data():
        if os.path.exists(USER_DATA_FILE):
            try:
                with open(USER_DATA_FILE, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def save_user_data(data):
        with open(USER_DATA_FILE, 'w') as f:
            json.dump(data, f, indent=4)

    def load_vault_data(username, password):
        vault_file = f"{VAULT_FILE_PREFIX}{username}.enc"
        if os.path.exists(vault_file):
            with open(vault_file, 'r') as f:
                encrypted_data = f.read()
            return decrypt_data(encrypted_data, password)
        return []

    def save_vault_data(username, password, data):
        vault_file = f"{VAULT_FILE_PREFIX}{username}.enc"
        encrypted_data = encrypt_data(data, password)
        with open(vault_file, 'w') as f:
            f.write(encrypted_data)

    # Функции для проверки пароля
    def check_password_strength(password):
        strength = 0
        feedback = []

        if len(password) >= 8:
            strength += 1
        else:
            feedback.append("• At least 8 characters")

        if re.search(r"\d", password):
            strength += 1
        else:
            feedback.append("• Include digits")

        if re.search(r"[A-Z]", password):
            strength += 1
        else:
            feedback.append("• Include uppercase letters")

        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            strength += 1
        else:
            feedback.append("• Include special characters")

        return strength, feedback

    # Функции UI
    def show_snackbar(message, color=None):
        snackbar = ft.SnackBar(
            ft.Text(message),
            bgcolor=color or PRIMARY_COLOR
        )
        page.snack_bar = snackbar
        snackbar.open = True
        page.update()

    def navigate_to(page_name):
        content_area.content = pages[page_name]
        page.update()

    def register_user(e):
        username = register_username.value.strip()
        password = register_password.value
        confirm_password = register_confirm_password.value

        if not username or not password:
            show_snackbar("Please fill all fields", ACCENT_COLOR)
            return

        if password != confirm_password:
            show_snackbar("Passwords don't match", ACCENT_COLOR)
            return

        user_data = load_user_data()
        if username in user_data:
            show_snackbar("Username already exists", ACCENT_COLOR)
            return

        # Сохраняем хэш пароля
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        user_data[username] = password_hash
        save_user_data(user_data)

        # Создаем пустой зашифрованный vault
        save_vault_data(username, password, [])

        show_snackbar("Registration successful! Please login.", PRIMARY_COLOR)
        navigate_to("login")

    def login_user(e):
        username = login_username.value.strip()
        password = login_password.value

        if not username or not password:
            show_snackbar("Please fill all fields", ACCENT_COLOR)
            return

        user_data = load_user_data()
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        if username not in user_data or user_data[username] != password_hash:
            show_snackbar("Invalid username or password", ACCENT_COLOR)
            return

        # Загружаем данные vault
        vault_data = load_vault_data(username, password)
        if vault_data is None:
            show_snackbar("Failed to decrypt vault. Invalid password?", ACCENT_COLOR)
            return

        global current_user, fernet
        current_user = username
        fernet = Fernet(generate_key_from_password(password))

        # Обновляем данные vault
        passwords_list.clear()
        passwords_list.extend(vault_data)
        update_password_list()

        show_snackbar(f"Welcome back, {username}!", PRIMARY_COLOR)
        navigate_to("vault")

    def add_password(e):
        service = add_service.value.strip()
        username_val = add_username.value.strip()
        password_val = add_password_field.value

        if not service or not username_val or not password_val:
            show_snackbar("Please fill all fields", ACCENT_COLOR)
            return

        new_entry = {
            "id": len(passwords_list) + 1,
            "service": service,
            "username": username_val,
            "password": password_val,
            "date_added": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "category": category_dropdown.value or "Other"
        }

        passwords_list.append(new_entry)
        save_vault_data(current_user, login_password.value, passwords_list)

        # Очищаем форму
        add_service.value = ""
        add_username.value = ""
        add_password_field.value = ""
        password_strength_text.value = ""

        update_password_list()
        show_snackbar("Password added successfully!", PRIMARY_COLOR)
        page.update()

    def generate_password(e):
        length = 16
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        generated = ''.join(random.choice(chars) for _ in range(length))

        add_password_field.value = generated
        update_password_strength(None)
        page.update()

    def update_password_strength(e):
        password = add_password_field.value
        if not password:
            password_strength_text.value = ""
            page.update()
            return

        strength, feedback = check_password_strength(password)

        if strength == 0:
            password_strength_text.value = "Very Weak"
            password_strength_text.color = "red"
        elif strength == 1:
            password_strength_text.value = "Weak"
            password_strength_text.color = "orange"
        elif strength == 2:
            password_strength_text.value = "Medium"
            password_strength_text.color = "yellow"
        elif strength == 3:
            password_strength_text.value = "Strong"
            password_strength_text.color = "lightgreen"
        else:
            password_strength_text.value = "Very Strong"
            password_strength_text.color = "green"

        page.update()

    def update_password_list():
        password_list_view.controls.clear()

        search_term = search_field.value.lower()
        category_filter = category_filter_dropdown.value

        filtered_passwords = [
            p for p in passwords_list
            if (search_term in p["service"].lower() or
                search_term in p["username"].lower() or
                search_term in p["category"].lower()) and
               (category_filter is None or category_filter == "All" or
                p["category"] == category_filter)
        ]

        if not filtered_passwords:
            password_list_view.controls.append(
                ft.Container(
                    content=ft.Column([
                        ft.Text("🔍", size=40),
                        ft.Text("No passwords found", size=16, weight="bold"),
                        ft.Text("Try adjusting your search or add a new password", color=SECONDARY_COLOR)
                    ], alignment="center", horizontal_alignment="center"),
                    padding=40,
                    alignment=ft.alignment.center
                )
            )
        else:
            for pwd in filtered_passwords:
                password_list_view.controls.append(
                    ft.Container(
                        content=ft.Column([
                            ft.Row([
                                ft.Text("🔒", size=16),
                                ft.Text(pwd["service"], size=16, weight="bold", expand=True),
                                ft.PopupMenuButton(
                                    items=[
                                        ft.PopupMenuItem(text="Reveal",
                                                         on_click=lambda e, p=pwd: reveal_password(e, p)),
                                        ft.PopupMenuItem(text="Copy", on_click=lambda e, p=pwd: copy_password(e, p)),
                                        ft.PopupMenuItem(text="Edit",
                                                         on_click=lambda e, p=pwd: edit_password_dialog(e, p)),
                                        ft.PopupMenuItem(text="Delete",
                                                         on_click=lambda e, p=pwd: delete_password_dialog(e, p)),
                                    ]
                                )
                            ]),
                            ft.Text(f"Username: {pwd['username']}", size=14),
                            ft.Text(f"Category: {pwd['category']}", size=12, color=SECONDARY_COLOR),
                            ft.Text(f"Added: {pwd['date_added']}", size=12, color=SECONDARY_COLOR),
                        ]),
                        padding=15,
                        border_radius=10,
                        bgcolor=CARD_COLOR,
                        margin=ft.margin.only(bottom=10)
                    )
                )

        page.update()

    def reveal_password(e, pwd):
        dlg = ft.AlertDialog(
            title=ft.Text(f"Password for {pwd['service']}"),
            content=ft.Text(pwd["password"], selectable=True, size=18),
            actions=[ft.TextButton("OK", on_click=close_dialog)],
        )
        page.dialog = dlg
        dlg.open = True
        page.update()

    def copy_password(e, pwd):
        page.set_clipboard(pwd["password"])
        show_snackbar("Password copied to clipboard!", PRIMARY_COLOR)

    def edit_password_dialog(e, pwd):
        edit_service.value = pwd["service"]
        edit_username.value = pwd["username"]
        edit_password.value = pwd["password"]
        edit_category.value = pwd["category"]
        editing_id = pwd["id"]

        def save_edit(e):
            for i, item in enumerate(passwords_list):
                if item["id"] == editing_id:
                    passwords_list[i] = {
                        "id": editing_id,
                        "service": edit_service.value,
                        "username": edit_username.value,
                        "password": edit_password.value,
                        "date_added": pwd["date_added"],
                        "category": edit_category.value
                    }
                    break

            save_vault_data(current_user, login_password.value, passwords_list)
            update_password_list()
            page.dialog.open = False
            show_snackbar("Password updated successfully!", PRIMARY_COLOR)
            page.update()

        edit_dlg = ft.AlertDialog(
            title=ft.Text("Edit Password"),
            content=ft.Column([
                ft.TextField(label="Service", value=pwd["service"], autofocus=True),
                ft.TextField(label="Username", value=pwd["username"]),
                ft.TextField(label="Password", value=pwd["password"], password=True),
                ft.Dropdown(
                    label="Category",
                    value=pwd["category"],
                    options=[
                        ft.dropdown.Option("Social Media"),
                        ft.dropdown.Option("Email"),
                        ft.dropdown.Option("Work"),
                        ft.dropdown.Option("Finance"),
                        ft.dropdown.Option("Shopping"),
                        ft.dropdown.Option("Other"),
                    ]
                )
            ], tight=True),
            actions=[
                ft.TextButton("Cancel", on_click=close_dialog),
                ft.TextButton("Save", on_click=save_edit),
            ],
            actions_alignment="end"
        )

        page.dialog = edit_dlg
        edit_dlg.open = True
        page.update()

    def delete_password_dialog(e, pwd):
        def confirm_delete(e):
            passwords_list[:] = [p for p in passwords_list if p["id"] != pwd["id"]]
            save_vault_data(current_user, login_password.value, passwords_list)
            update_password_list()
            page.dialog.open = False
            show_snackbar("Password deleted successfully!", PRIMARY_COLOR)
            page.update()

        dlg = ft.AlertDialog(
            title=ft.Text("Confirm Delete"),
            content=ft.Text(f"Are you sure you want to delete the password for {pwd['service']}?"),
            actions=[
                ft.TextButton("Cancel", on_click=close_dialog),
                ft.TextButton("Delete", on_click=confirm_delete),
            ],
        )
        page.dialog = dlg
        dlg.open = True
        page.update()

    def close_dialog(e):
        page.dialog.open = False
        page.update()

    def logout(e):
        global current_user, fernet
        current_user = None
        fernet = None
        passwords_list.clear()
        navigate_to("login")
        show_snackbar("Logged out successfully", PRIMARY_COLOR)

    def open_add_dialog(e):
        add_password_dialog.open = True
        page.update()

    # Элементы UI для регистрации
    register_username = ft.TextField(label="Username", autofocus=True, width=300)
    register_password = ft.TextField(label="Master Password", password=True, can_reveal_password=True, width=300)
    register_confirm_password = ft.TextField(label="Confirm Master Password", password=True, can_reveal_password=True,
                                             width=300)

    register_page = ft.Container(
        content=ft.Column([
            ft.Text("🔒", size=80),
            ft.Text("Vaultron", size=40, weight="bold"),
            ft.Text("Create Your Secure Vault", size=16, color=SECONDARY_COLOR),
            ft.Divider(height=40),
            register_username,
            register_password,
            register_confirm_password,
            ft.Divider(height=20),
            ft.ElevatedButton(
                "Register",
                on_click=register_user,
                width=300,
                height=50,
                bgcolor="blue",
                color="white"
            ),
            ft.TextButton(
                "Already have an account? Login",
                on_click=lambda e: navigate_to("login")
            )
        ], alignment="center", horizontal_alignment="center"),
        alignment=ft.alignment.center,
        padding=40
    )

    # Элементы UI для входа
    login_username = ft.TextField(label="Username", autofocus=True, width=300)
    login_password = ft.TextField(label="Master Password", password=True, can_reveal_password=True, width=300)

    login_page = ft.Container(
        content=ft.Column([
            ft.Text("🔒", size=80),
            ft.Text("Vaultron", size=40, weight="bold"),
            ft.Text("Unlock Your Secure Vault", size=16, color=SECONDARY_COLOR),
            ft.Divider(height=40),
            login_username,
            login_password,
            ft.Divider(height=20),
            ft.ElevatedButton(
                "Login",
                on_click=login_user,
                width=300,
                height=50,
                bgcolor="blue",
                color="white"
            ),
            ft.TextButton(
                "Don't have an account? Register",
                on_click=lambda e: navigate_to("register")
            )
        ], alignment="center", horizontal_alignment="center"),
        alignment=ft.alignment.center,
        padding=40
    )

    # Элементы UI для vault
    passwords_list = []

    search_field = ft.TextField(
        label="Search passwords",
        width=300,
        on_change=lambda e: update_password_list(),
        suffix_icon="search"
    )

    category_filter_dropdown = ft.Dropdown(
        label="Filter by category",
        width=200,
        options=[
            ft.dropdown.Option("All"),
            ft.dropdown.Option("Social Media"),
            ft.dropdown.Option("Email"),
            ft.dropdown.Option("Work"),
            ft.dropdown.Option("Finance"),
            ft.dropdown.Option("Shopping"),
            ft.dropdown.Option("Other"),
        ],
        value="All",
        on_change=lambda e: update_password_list()
    )

    password_list_view = ft.ListView(expand=True, spacing=10)

    add_service = ft.TextField(label="Service", width=300)
    add_username = ft.TextField(label="Username", width=300)
    add_password_field = ft.TextField(
        label="Password",
        password=True,
        can_reveal_password=True,
        width=250,
        on_change=update_password_strength
    )
    password_strength_text = ft.Text("", size=12)

    category_dropdown = ft.Dropdown(
        label="Category",
        width=300,
        options=[
            ft.dropdown.Option("Social Media"),
            ft.dropdown.Option("Email"),
            ft.dropdown.Option("Work"),
            ft.dropdown.Option("Finance"),
            ft.dropdown.Option("Shopping"),
            ft.dropdown.Option("Other"),
        ],
        value="Other"
    )

    # Создаем диалог добавления пароля
    add_password_dialog = ft.AlertDialog(
        modal=True,
        title=ft.Text("Add New Password"),
        content=ft.Column([
            add_service,
            add_username,
            ft.Row([
                add_password_field,
                ft.IconButton(icon="autorenew", tooltip="Generate strong password", on_click=generate_password)
            ]),
            ft.Row([password_strength_text]),
            category_dropdown
        ], tight=True),
        actions=[
            ft.TextButton("Cancel", on_click=close_dialog),
            ft.TextButton("Add", on_click=add_password),
        ],
        actions_alignment="end"
    )

    vault_page = ft.Column([
        ft.Row([
            ft.Text("Your Vault", size=28, weight="bold", expand=True),
            ft.IconButton(icon="logout", tooltip="Logout", on_click=logout)
        ], alignment="spaceBetween"),

        ft.Divider(),

        ft.Row([
            search_field,
            category_filter_dropdown,
            ft.ElevatedButton("Add New", on_click=open_add_dialog)
        ], alignment="spaceBetween"),

        ft.Divider(height=20),

        ft.Container(
            content=password_list_view,
            border=ft.border.all(1, "#333333"),
            border_radius=10,
            padding=15,
            expand=True
        ),

        ft.Divider(height=20),

        ft.Row([
            ft.Text(f"Total passwords: {len(passwords_list)}", style="italic"),
            ft.Text("Vaultron - Your passwords are encrypted and secure", style="italic")
        ], alignment="spaceBetween")
    ])

    edit_service = ft.TextField(label="Service")
    edit_username = ft.TextField(label="Username")
    edit_password = ft.TextField(label="Password", password=True)
    edit_category = ft.Dropdown(
        label="Category",
        options=[
            ft.dropdown.Option("Social Media"),
            ft.dropdown.Option("Email"),
            ft.dropdown.Option("Work"),
            ft.dropdown.Option("Finance"),
            ft.dropdown.Option("Shopping"),
            ft.dropdown.Option("Other"),
        ]
    )

    # Собираем все страницы вместе
    pages = {
        "register": register_page,
        "login": login_page,
        "vault": vault_page
    }

    content_area = ft.Container(content=login_page, expand=True)

    # Запускаем приложение
    page.add(content_area)
    page.dialog = add_password_dialog


ft.app(target=main)