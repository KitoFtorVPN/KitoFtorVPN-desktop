# KitoFtorVPN Desktop

Windows-клиент KitoFtorVPN на базе AmneziaWG 2.0.

## Возможности

- Подключение к VPN одним кликом
- Обход VPN для выбранных сайтов (split tunneling)
- Автозапуск при старте Windows
- Автоподключение при запуске
- Хранение конфигов и токенов с шифрованием Windows DPAPI
- Авторизация: email, Google, Telegram, гостевой режим
- Автообновления через GitHub Releases

## Установка

Скачай последнюю версию `KitoFtorVPN-Setup.exe` со страницы [Releases](https://github.com/KitoFtorVPN/KitoFtorVPN-desktop/releases) и запусти.

Для работы приложения требуются права администратора (необходимы для создания TUN-интерфейса и настройки маршрутов).

## Требования

- Windows 10 / 11 x64

## Стек

- [Electron](https://www.electronjs.org/) — UI (HTML/CSS/JS)
- [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) — VPN-движок (Go)
- [Wintun](https://www.wintun.net/) — TUN-драйвер
- [electron-builder](https://www.electron.build/) — сборка установщика
- [electron-updater](https://github.com/electron-userland/electron-updater) — автообновления

## Сборка из исходников

Требуется Node.js 18+ и Go 1.21+.

```bash
# Установка зависимостей
npm install

# Запуск в режиме разработки
npm start

# Сборка установщика
npm run dist

# Сборка и публикация релиза на GitHub (нужен GH_TOKEN)
npm run publish
```

Установщик появится в папке `dist/`.

## Структура

```
KitoFtorVPN/
├── main.js           — главный процесс Electron
├── preload.js        — IPC-мост для renderer-процесса
├── package.json      — зависимости и конфиг electron-builder
├── ui/               — HTML-страницы интерфейса
│   ├── login.html
│   ├── main.html
│   ├── settings.html
│   ├── whitelist.html
│   └── import.html
├── bin/              — Go-хелпер и TUN-драйвер
│   ├── kitoftor-tunnel.exe
│   └── wintun.dll
└── build/            — иконки приложения и трея
```

## Сайт

[kitoftorvpn.fun](https://kitoftorvpn.fun)
